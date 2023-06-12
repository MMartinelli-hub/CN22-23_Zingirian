/*
 * Selective Repeat Protocol Implementation
 *
 * This program demonstrates the implementation of the Selective Repeat protocol
 * for reliable data transfer over a network. It uses asynchronous I/O, support
 * for timeouts, and non-blocking I/O for efficient packet handling.
 *
 * Functions:
 * - main: Initialization and runs the application
 * - myio: Handles packet receiving
 * - mytimer: Handles the timeouts
 *
 */

#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>

#define N 5 // size of the window: 5 packet


// define the struct of a packet
// we don't put an ID on the packet bc it will be identified by its position on the buffer
struct packet {
    int is_acked;   // Ack flag: indicates whether the packet has been acknowledged
    int timeout;    // Timeout value for the packet
	// in go-back-n we would have a timeout for the window, not for the packet
} win[2*N]; // 2 times N bc for each packet we have (1) the sent packet and (2) the ack packet
// win is set to zero by default bc we are in a static area


sigset_t mask; // var used to specify a mask of signals which should be blocked

int winstart; // var used to keep track of the starting second of the window
int seconds; // var used to keep track of the elapsed seconds


// Timer handler function
/* 
This function is invoked when a timer signal is received.
It checks for any unacknowledged packets and resends them if necessary.
*/
void mytimer(int num) {
    int i; // var used to keep track of the elapsing seconds
    seconds++;  // Increment the global seconds variable
    printf("Timer Call: %d\n", seconds);
    
    for(i = winstart; i < winstart + N; i++) { // send all packets of the window in sequence
		// if the packet is not ack AND its timeout is elapsed
		if((!win[i % (2*N)].is_acked) && (win[i % (2*N)].timeout <= seconds)) {  
			printf("Timer Handler: Send Packet %d\n",i);
			win[i % (2*N)].timeout = seconds + 4; // set the timeout for the ack
		}
	}
}


// I/O handler function
/*
 *
 * This function is invoked when an I/O event occurs.
 * It handles packet receiving, checks for acknowledgments,
 * and sends new packets as necessary.
 *
 * RFC References: RFC 793, RFC 1122
 */
void myio(int num) {
    int t, i;
    int ack_no;
    char buffer[101]; // the number of received character supported by the buffer
	// this buffer supports 100 characters, the 101th will be used as a separator

	/*
	struct pollfd {
		int   fd;          // file descriptor 
		short events;      // requested events 
		short revents;     // returned events 
	};

	The caller should specify the number of items in the fds array in nfds.

	The field fd contains a file descriptor for an open file.  If this field is negative, then the corre‐
	sponding events field is ignored and the revents field returns zero.  (This provides an easy  way  of
	ignoring a file descriptor for a single poll() call: simply negate the fd field.  Note, however, that
	this technique can't be used to ignore file descriptor 0.)

	The field events is an input parameter, a bit mask specifying the events the  application  is  inter‐
	ested  in  for  the  file descriptor fd.  This field may be specified as zero, in which case the only
	events that can be returned in revents are POLLHUP, POLLERR, and POLLNVAL (see below).

	The field revents is an output parameter,  filled  by  the  kernel  with  the  events  that  actually
	occurred.   The  bits returned in revents can include any of those specified in events, or one of the
	values POLLERR, POLLHUP, or POLLNVAL.  (These three bits are meaningless in  the  events  field,  and
	will be set in the revents field whenever the corresponding condition is true.)

	If  none  of  the  events requested (and no error) has occurred for any of the file descriptors, then
	poll() blocks until one of the events occurs.
	*/
    struct pollfd fd[1];
    
	fd[0].fd = 0; // File descriptor 0 represents standard input (stdin)
    fd[0].events = POLLIN; // Set the (requested) event mask to POLLIN (= data to read) to monitor for incoming data
    fd[0].revents = 0; // Clear the revents (returned event) field initially

    printf("I/O called\n");
   
    if (-1 == poll(fd, 1, 0)) { // Poll the file descriptor for events
        perror("poll error"); // Print an error message if poll fails
        return;
    }

    if (fd[0].revents == POLLIN) { // Check if the (returned) event is POLLIN (incoming data)
       	for (i = 0; (t = read(fd[0].fd, buffer + i, 100 - i)) > 0; i += t) {} // read in the buffer the text put in the fd by the pool operation
        
        // #define	EAGAIN 11	/* No more processes */
		// if the read ended (t == -1) and this was not bc there are no more processes, an error occured
		if (t == -1 && (errno != EAGAIN)) 
			perror("Read failed"); 	

		buffer[i] = 0;  // Null-terminate the buffer
        sscanf(buffer, "%d", &ack_no);  // Extract the acknowledgment number from the buffer
        printf("Acked: %d\n", ack_no);
        
        if (ack_no >= winstart && ack_no < winstart + N) {   // Check if the acknowledgment is within the window
            win[ack_no % (2 * N)].is_acked = 1; // set the 'ack flag' in 'struct packet' at 'true' 
            
			/*
			now we scan every packet in the window in sequence
			for every ack packet:
				- we move the window of 1
				- we set the ack flag of the new pointed position at zero
				- we send the new pointed packet and set its timeout
			*/
            for (i = winstart; i < winstart + N && win[i % (2 * N)].is_acked; i++) {
                win[(i + N) % (2 * N)].is_acked = 0;
                win[(i + N) % (2 * N)].timeout = seconds + 4;
                printf("I/O Handler: sending packet %d\n", i + N);
            }
            
            winstart = i;   // Update the window start position
        }
    }
}


int main() {
    /*
	struct itimerval {
		struct	timeval it_interval;	// timer interval 
		struct	timeval it_value;		// current value 
	};
	*/
    struct itimerval ti;

    int s = 0; // socket 0 = std input
    int flags;
    

    // Set the process to receive asynchronous I/O signals

	/*
	fcntl - manipulate file descriptor
	Usage: int fcntl(int fd, int cmd, ... // arg //);
	
	fcntl() performs one of the operations described below on the open file descriptor fd.  The operation
	is determined by cmd.

	fcntl() can take an optional third argument.  Whether or not this argument is required is  determined
	by  cmd.   The required argument type is indicated in parentheses after each cmd name (in most cases,
	the required type is int, and we identify the argument using the name arg), or void is  specified  if
	the argument is not required.

	Managing signals
	F_GETOWN, F_SETOWN, F_GETOWN_EX, F_SETOWN_EX, F_GETSIG and F_SETSIG are used to manage I/O availability signals:

	F_SETOWN (int)
		Set  the  process ID or process group ID that will receive SIGIO and SIGURG signals for events
		on file descriptor fd to the ID given in arg.  A process ID is specified as a positive  value;
		a process group ID is specified as a negative value.  Most commonly, the calling process spec‐
		ifies itself as the owner (that is, arg is specified as getpid(2)).

		If you set the O_ASYNC status flag on a file  descriptor  by  using  the  F_SETFL  command  of
		fcntl(),  a  SIGIO  signal  is  sent  whenever  input  or output becomes possible on that file
		descriptor.  F_SETSIG can be used to obtain delivery of a signal other than  SIGIO.   If  this
		permission check fails, then the signal is silently discarded.

		Sending  a  signal  to  the owner process (group) specified by F_SETOWN is subject to the same
		permissions checks as are described for kill(2), where the sending process  is  the  one  that
		employs F_SETOWN (but see BUGS below).

		If  the  file  descriptor fd refers to a socket, F_SETOWN also selects the recipient of SIGURG
		signals that are delivered when out-of-band data arrives on that socket.  (SIGURG is  sent  in
		any situation where select(2) would report the socket as having an "exceptional condition".)

	File status flags
	Each  open  file description has certain associated status flags, initialized by open(2) and possibly
	modified by fcntl().  Duplicated file descriptors (made with dup(2), fcntl(F_DUPFD),  fork(2),  etc.)
	refer to the same open file description, and thus share the same file status flags.

	F_GETFL (void)
		Get the file access mode and the file status flags; arg is ignored.
	*/
    flags = fcntl(s, F_SETOWN, getpid()); // Set the process ID (in this case itself) that will receive SIGIO signals
    flags = fcntl(s, F_GETFL); // Get the file status flags of the socket: check if the socket has been set up correctly
    
	if (flags == -1) { // if an error occured in setting up the socket
		perror("Error in F_SETOWN: fcntl-F_GETFL returned -1"); 
		return 1;
	}

	/*
	File status flag
	F_SETFL (int)
		Set  the  file  status  flags  to  the  value  specified  by arg.  
		File access mode (O_RDONLY, O_WRONLY, O_RDWR) and file creation flags (i.e., O_CREAT, O_EXCL, O_NOCTTY,  O_TRUNC) in arg are ignored.   
		On Linux this command can change only the O_APPEND, O_ASYNC, O_DIRECT, O_NOATIME, and O_NONBLOCK flags.  
		It is not possible to change the O_DSYNC  and  O_SYNC  flags;  see BUGS, below.
	*/
    flags = fcntl(s, F_SETFL, flags | O_ASYNC | O_NONBLOCK); // Set the file status flags to enable asynchronous and non-blocking I/O
    
	if (flags == -1) { // if an error occured in setting up the socket 
		perror("Error in F_SETFL: fcntl-F_SETFL returned -1"); 
		return 1;
	}

    
    /*
	The sigaction() system call is used to change the action taken by a process on receipt of a specific signal.

	The sigaction structure is defined as something like:
		struct sigaction {
			void     	(*sa_handler)(int);
			void     	(*sa_sigaction)(int, siginfo_t *, void *);
			sigset_t   	sa_mask;
			int        	sa_flags;
			void     	(*sa_restorer)(void);
		};

	The sa_restorer field is not intended for application use.

	sa_handler specifies the action to be associated with signum and may be SIG_DFL for the default action, SIG_IGN to ignore this signal, or a pointer to a signal handling function.  
	This function receives the signal number as its only argument.

	sa_mask  specifies  a  mask  of  signals which should be blocked (i.e., added to the signal mask of the thread in which the signal  handler  is invoked) during execution of the signal handler.  
	In addition, the signal which triggered the handler will be blocked, unless the SA_NODEFER flag is used.

	sa_flags specifies a set of flags which modify the behavior of the signal.

	The siginfo_t argument to sa_sigaction is a struct with  the  following fields: 
			siginfo_t {
			int	si_signo;	// Signal number 
			int si_errno;	// An errno value 
			int si_code;	// Signal code 
			... (see "man sigaction" for more)
		}
	si_signo, si_errno and si_code are defined for all signals (si_errno is generally unused on Linux).
	*/
	struct sigaction sa_io; // used to specify the action(s) upon I/O signal
	struct sigaction sa_timer; // used to specify the action(s) over timer

	// Set up signal handlers
    sa_io.sa_handler = myio; // Set the I/O signal handler function
    sa_timer.sa_handler = mytimer; // Set the timer signal handler function

    // Set up timer
    ti.it_interval.tv_sec = 1; // Set the timer to trigger every 1 second
    ti.it_interval.tv_usec = 0;
    ti.it_value.tv_sec = 1; // Set the initial timer value to 1 second
    ti.it_value.tv_usec = 0;

	/*
	int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
	
	The  function  setitimer()  sets the specified timer to the value in new_value.  If old_value is non-
	NULL, the old value of the timer (i.e., the same information as returned by  getitimer())  is  stored
	there.

	Timers  decrement  from it_value to zero, generate a signal, and reset to it_interval.  A timer which
	is set to zero (it_value is zero or the timer expires and it_interval is zero) stops.
	*/
    setitimer(ITIMER_REAL, &ti, NULL); // Start the real-time timer 

    // Register signal handlers
    if (-1 == sigaction(SIGIO, &sa_io, NULL)) { // Register the I/O signal handler for SIGIO
        perror("Sigaction SIGIO error"); // Print an error message if sigaction fails
        return 1;
    }
    if (-1 == sigaction(SIGALRM, &sa_timer, NULL)) { // Register the timer signal handler for SIGALRM
        perror("Sigaction SIGALRM error"); // Print an error message if sigaction fails
        return 1;
    }

    // Unblock signals
    if (-1 == sigemptyset(&mask)) { // Initialize an empty signal set
        perror("Sigemptyset error"); // Print an error message if sigemptyset fails
        return 1;
    }
    if (-1 == sigaddset(&mask, SIGIO)) { // Add SIGIO to the signal set
        perror("Sigaddset SIGIO error"); // Print an error message if sigaddset fails
        return 1;
    }
    if (-1 == sigaddset(&mask, SIGALRM)) { // Add SIGALRM to the signal set
        perror("Sigaddset SIGALRM error"); // Print an error message if sigaddset fails
        return 1;
    }
    if (-1 == sigprocmask(SIG_UNBLOCK, &mask, NULL)) { // Unblock the signals in the signal set
        perror("Sigprocmask error"); // Print an error message if sigprocmask fails
        return 1;
    }

    // Run the application
    while (1) {
        sleep(1000); // Sleep for 1000 milliseconds (1 second)
    }

    return 0;
}