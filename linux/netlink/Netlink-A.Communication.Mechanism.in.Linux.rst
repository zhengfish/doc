-------------------------------------------
Netlink: A Communication Mechanism in Linux
-------------------------------------------

.. code-block:: rst

   Netlink: 一种Linux通讯机制

Santosh Ramroop Yadav , August 14, 2015 / 279 0 Comments

From: http://opensourceforu.com/2015/08/netlink-a-communication-mechanism-in-linux/

Netlink is a Linux kernel socket interface, which is used for inter-process communication between the user space and the kernel, and also between different user space processes. It reduces dependence on system calls, ioctls and proc files. Netlink also helps preserve kernel purity.

There are various ways by which processes in the user space can communicate with the kernel. These are system calls, ioctl and the proc file system. The problem with system calls is that they are linked statically to kernel code. So, any new feature that is to be provided has to be compiled with the kernel, but with dynamic linking modules such as device drivers, any feature that these modules want to provide cannot always be preconfigured as a system call. Similarly, for every new feature, it is hard to provide communication through the file system. All these communication mechanisms also require that the processes initiate the communication -- the kernel cannot initiate the communication.

.. code-block:: rst

   Netlink是一种Linux内核套接字接口，用来实现用户空间和内核空间之间的进程间通讯，也可以实现用户空间进程之间的通讯。
   它减少了对系统调用、IO控制和Proc文件系统的依赖。Netlink也有助于保持内核纯洁性。
   Linux提供各种各样的用户空间进程和内核之间通讯的方式，包括系统调用、IO控制和Proc文件系统。
   系统调用的问题是必须静态链接到内核代码，所以，任何想要实现的新特征必须编译到内核代码中，
   但对于动态链接的设备驱动而言，其将要实现的某些特征往往又不能预先配置成某个系统调用。
   相似的情况包括，任何新特征都不得不通过文件系统提供通讯。
   所有的这些通讯机制都要求进程初始化通讯过程 -- 而内核不能初始化该通讯过程。

Netlink socket
==============

Netlink socket is a communication mechanism used between the user space processes and also for communication between processes and the kernel. It can also be used for communication between user space threads and the kernel. It is a full duplex communication mechanism, that is, the kernel itself can initiate the communication. One of the advantages of this mechanism is that, in the user space, popular socket APIs that software programmers are familiar with are used for Netlink communication, so no new study is required. Netlink sockets are easier to add than system calls, ioctls and proc files. all of which will start polluting the kernel. If these are added for every new feature, then later on, it becomes difficult to remove these features — a problem kernel developers are facing currently in the case of the proc file system. In case of Netlink sockets, only a protocol type macro needs to be inserted in the netlink.h file, which resides in include/uapi/linux/netlink.h, and processes and the kernel can start communicating immediately through the socket API. Netlink socket is an asynchronous communication method, that is, it queues the messages to be sent in the receiver's Netlink queue. One of the features of a Netlink socket is that it also supports multicast communication, i.e., one process can send a message to a Netlink group address, and many processes can listen on this group address. Since in the user space it is implemented through the socket API, this is an easy-to-use communication mechanism.

.. code-block:: rst

   Netlink套接字是一种实现用户空间进程之间通讯、以及用户进程和内核之间通讯的机制，
   也可以用作用户空间线程和内核之间通讯。这是一种全双工的通讯机制，即，内核自己能发起
   这个通讯过程。其中一个优点是，在用户空间，Netlink采用软件程序员们广泛使用的套接字
   编程接口API，不需要重新学习。Netlink套接字也比系统调用、IO控制和Proc文件更容易添加。
   所有的这些都会污染内核。如果为了每个新特征都添加这些，慢慢地，这些特征将会难以删除
   -- 比如当前内核开发者就面临proc文件系统（难以去除）的问题。如果采用Netlink套接字，
   只需要添加一个协议类型宏定义到位于 include/uapi/linux/netlink.h 的头文件中，然后
   用户进程和内核就立即可以通过套接字API进行通讯了。Netlink套接字是一种异步通讯方法，
   即，它把将要发送的消息加入接受者的Netlink队列。Netlink套接字的特征之一是支持多播，
   就是说，一个用户进程能够把一个消息发送一个Netlink组地址，而多个进程能够同时监听
   这个组地址。由于在用户空间通过套接字API方式来实现，这使其成为一个易于使用的通讯方式。

The basics of Netlink sockets
=============================

To use Netlink sockets in code, a standard socket API is used, which is as follows:

.. code-block:: rst

   要在代码中使用Netlink套接字，需要使用一个如下的标准套接字API接口：

.. code-block:: c

    int socket(int domain, int type, int protocol);

Here, domain specifies the protocol family used for communication which is defined in sys/socket.h; domain in the case of Netlink is AF_NETLINK.
type specifies the way in which communication is done. In the case of Netlink, SOCK_RAW or SOCK_DGRAM can be used.
protocol specifies which Netlink feature is to be used. Various features are specified in include/uapi/linux/netlink.h, which are NETLINK_GENERIC, NETLINK_ROUTE, NETLINK_FIREWALL, etc. You can also add a custom Netlink protocol easily by adding the macro in this file.
For each Netlink protocol type, up to 32 multicast groups can be specified in code. A multicast group in Netlink is a 32-bit bitmask, where each bit represents a group. Using this multicast feature, multiple processes and kernel modules can communicate with each other with a lesser number of system calls.
To understand Netlink sockets in the user space, the following data structures need to be understood.

.. code-block:: rst

   此处用domain形参来指定通讯所用的协议族，定义在sys/socket.h文件中；在Netlink中domain的
   值是AF_NETLINK。type形参用来指定Netlink将要使用的特征。各种各样的特征定义在
   include/uapi/linux/netlink.h文件中，有NETLINK_GENERIC, NETLINK_ROUTE, NETLINK_FIREWALL等等。
   你可以通过在此文件中添加一个宏来自定义一个Netlink协议。对每个Netlink协议类型，可以在代码中
   定义多达32个多播组。在Netlink中一个多播组是一个32位掩码，其中每一位就是一个组。采用这个多播
   特点，多个用户进程和内核模块之间能够以较少的系统调用相互通讯。

   为了要理解在用户空间的Netlink套接字，下面的数据结构需要被理解。

.. code-block:: c

    struct sockaddr_nl;
    struct nlmsghdr;
    struct iovec;
    struct msghdr;

    struct sockaddr_nl (include/uapi/linux/netlink.h)
    {
        __kernel_sa_family_t nl_family;
        unsigned short nl_pad;
        __u32 nl_pid;
        __u32 nl_groups;
    };

In the above code, let's look at what certain terms stand for.

* nl_family: This is the protocol family to be used, which is AF_NETLINK.
* nl_pad: This is used for padding.
* nl_pid: This is the identification or the local address of the process. It is used if a process wants to send a unicast message to other processes or the kernel.
* nl_groups: This is a 32-bit bitmask used for multicast communication.
* nl_pid can be the PID of the process, which can be initialised as follows:

.. code-block:: rst

   在上面的代码，让我们来看看一些术语具体代表的含义。
* nl_family：是要采用的协议族，即AF_NETLINK。
* nl_pad：用于填充。
* nl_pid：是ID或进程的本地地址。如果一个进程想要发送的单播消息给其它进程或内核，需要使用它。
* nl_groups：用于多播通信的32位位掩码。
* nl_pid：可以是进程ID，可以如下方式初始化：

.. code-block:: c

    struct sockaddr_nl addr;
    addr.nl_pid = getpid();

If, in a process, each thread wants its own Netlink socket, then nl_pid can be initialised to:

.. code-block:: rst

   在某个进程中，如果每一个线程需要自己独立的Netlink套接字，那么nl_pid可以初始化成：

.. code-block:: c

    addr.nl_pid = pthread_self() << 16 | getpid();

Or it can be initialised to simple numbers as:

.. code-block:: rst

   或者可以被简单初始化为一个数字：

.. code-block:: c

    addr.nl_pid = 1;

Or any algorithm can be used to assign it a unique value.
nl_groups are used for multicast communication. Each bit in this field is a multicast address. Any process which needs to listen on a particular group should set the bit.
As an example, if a process wants to listen on multicast addresses 3 and 5, then the bits are stored as follows:

.. code-block:: rst

   或者采用一个给它赋予一个唯一值的算法。
   nl_groups被用于多播通讯。这个域中的每一位都是一个多播地址。任何想要监听一个特定组的进程应该设置该位。
   举例而言，如果某进程想要监听多播地址位3和5，那么地址位应该如下设置：

.. code-block:: c

    addr.nl_groups = 1<<3 | 1<<5;

If, for example, a process wants to send data to multicast group 3, then it will initialise the nl_groups field as follows:

.. code-block:: rst

   又例如，如果一个进程需要将数据发送到多播组3，那么应该初始化nl_groups字段如下：

.. code-block:: c

    addr.nl_groups = 1 << 3;

If the process wants to send to both the 3 and 5 groups, then nl_groups will be initialised as follows:

.. code-block:: rst

   如果该过程要发送到3和5两组，则nl_groups应该如下初始化

.. code-block:: c

    addr.nl_groups = 1<<3 | 1<<5;

nl_pid is used to identify a single process or kernel and nl_groups is used to identify multiple processes or kernel modules, where nl_pid = 0 is a special address, which is the kernel address.
The kernel requires each Netlink message to include the Netlink message header. Thus a Netlink message is a combination of a message header and message payload. An application allocates a buffer long enough to store both header and payload. The starting of the buffer holds the Netlink message header and it is followed by the payload. So just by typecasting the buffer address with the header structure, the header can be accessed, after which there is the payload. The header structure (include/uapi/linux/netlink.h) is as follows:

.. code-block:: c

    struct nlmsghdr
    {
        __u32 nlmsg_len;
        __u32 nlmsg_type;
        __u32 nlmsg_flags;
        __u32 nlmsg_seq;
        __u32 nlmsg_pid;
    };

In the code above, let's look at what certain terms mean:

* nlmsg_len: This is the length of the message to be transferred, including the header length.
* nlmsg_type: This is the type of message that is being transferred and is used by applications. This field is not used by the kernel.
* nlmsg_flags: This is used to give additional information.
* nlmsg_seq: This is the sequence number of the message and is used by applications. This field is not used by the kernel.
* nlmsg_pid: This is the identification of the process which sends the message and is used by applications. This field is not used by the kernel.

A Netlink message is a buffer that holds both the Netlink header and the Netlink payload. The buffer is passed to the Netlink core through iovec structure. The structure (include/uapi/linux/uio.h) definition is as follows:

.. code-block:: c

    struct iovec{
        void __user *iov_base;
        __kernel_size_t iov_len;
    };

In the above code, iov_base holds the base address of the Netlink message buffer, and iov_len holds the length of the Netlink message buffer, which is the size of the Netlink header and payload.
Socket messages are sent through the sendmsg API, which requires the msghdr structure as a parameter. The following fields of struct msghdr are useful:

.. code-block:: c

    struct msghdr
    {
        void *msg_name;
        int msg_namelen;
        struct iovec *msg_iov;
        __kernel_size_t msg_iovlen;
        //other fields not discussed
    };

In the above code

    msg_name is the base address of the struct sockaddr_nl variable, which holds information about the destination address.
    msg_namelen is the length of the structure, which is pointed by the msg_name field.
    msg_iov is the address of the iovec structure which holds the netlink message buffer.
    msg_iovlen is the length of the netlink message buffer.

Process-to-process unicast communication
========================================

Unicast sender example: The following header file needs to be included in an application:
----------------------

.. code-block:: c

    #include <sys/socket.h>
    #include <linux/netlink.h>

First, the application has to create a Netlink socket, which is done through the socket API as follows:

.. code-block:: c

    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

After creating the Netlink socket, the application has to bind the socket with the unique address as follows:

.. code-block:: c

    struct sockaddr_nl src_addr;

    //AF_NETLINK socket protocol
    src_addr.nl_family = AF_NETLINK;

    //application unique id
    src_addr.nl_pid = 1;

    //specify not a multicast communication
    src_addr.nl_groups = 0;

    //attach socket to unique id or address
    bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

After binding the socket with the unique address, the application has to define the destination address, message header, message payload, iovec structure and send the message using the sendmsg API as follows:

.. code-block:: c

    //total netlink message length
    #define NLINK_MSG_LEN 1024

    struct sockaddr_nl dest_addr;

    dest_addr.nl_family = AF_NETLINK;

    //destination process id
    dest_addr.nl_pid = 2;

    dest_addr.nl_groups = 0;

    //allocate buffer for netlink message which
    //is message header + message payload
    struct nlmsghdr *nlh =(struct nlmsghdr *) malloc(NLMSG_SPACE(NLINK_MSG_LEN));

Here, NLMSG_SPACE is the macro that gives an aligned length for the Netlink message.

.. code-block:: c

    //netlink message length
    nlh->nlmsg_len = NLMSG_SPACE(NLINK_MSG_LEN);

    //src application unique id
    nlh->nlmsg_pid = 1;

    nlh->nlmsg_flags = 0;

    //copy the payload to be sent
    strcpy(NLMSG_DATA(nlh), "Hello Process");

Here, the NLMSG_DATA macro is used to access the address of the payload.

.. code-block:: c

    //fill the iovec structure
    struct iovev iov;

    //netlink message header base address
    iov.iov_base = (void *)nlh;

    //netlink message length
    iov.iov_len = nlh->nlmsg_len;

    //define the message header for message
    //sending
    struct msghdr msg;

    msg.msg_name = (void *)&dest_addr;

    msg.msg_namelen = sizeof(dest_addr);

    msg.msg_iov = &iov;

    msg.msg_iovlen = 1;
    //send the message
    sendmsg(fd, &msg, 0);

Unicast receive example: In case of the receiver, first the Netlink socket will be created using a socket API, as it was in the case of the sender.
-----------------------

Then, like the sender, the receiver will bind its socket with the unique address, which will be the same as in the case of the sender. src_addr.nl_pid should be initialised as follows:

.. code-block:: c

    //receiver address or id
    src_addr.nl_pid = 2;

dest_addr will be used to receive the data which does not need to be initialised. In case of nlmsghdr, this structure is just cleared as follows:

.. code-block:: c

    memset(nlh, 0, NLMSG_SPACE(NLINK_MSG_PAYLOAD));

The rest of the code will be similar to the sender's code, but instead of the sendmsg API, the recvmsg API will be used as follows:

.. code-block:: c

    recvmsg(fd, &msg, 0);

This API will block until the message is received, after which the nlmsghdr variable nlh will get updated with the message header and payload, where the latter can be accessed as NLMSG_DATA(nlh) which will be a pointer to the payload.

Process-to-process multicast communication
==========================================

In case of receivers for multicast communication, the sockaddr_nl structure should be initialised as follows:

.. code-block:: c

    struct sockaddr_nl src_addr;
    //initialize the protocol as Netlink family

    src_adr.nl_family = AF_NETLINK;

    //assign the unique id to each application, here
    //2 is assigned for example
    src_addr.nl_pid = 2;

    //assign multicast addresses on which the process
    //wants to listen, for example all the process
    //wants to listen on multicast address 3 and 5
    src_addr.nl_groups = 1<<3 | 1<<5;

The rest of the code is similar to the unicast receiver code.
In case of a sender for multicast communication, the destination sockaddr_nl structure should be initialised as follows:

.. code-block:: c

    struct sockaddr_nl dest_addr;

    //initialize the protocol as Netlink family
    dest_addr.nl_family = AF_NETLINK;

    //suppose process wants to send multicast
    //message to all process with multicast
    //group 3
    dest_addr.nl_groups = 1<<3;

Kernel Netlink implementation
=============================

The kernel space API for Netlink is different from that for user space. To create a Netlink socket in the kernel, the following API is used:

.. code-block:: c

    struct sock* netlink_kernel_create(int unit,
    void (*input)(struct sock *sock, int len));

In the above code:

    unit is the protocol type, which is defined in include/uapi/linux/netlink.h; for example, NETLINK_GENERIC.
    input is the function pointer, which is called when the application sends data to the kernel with a unit type protocol.
    So to create a Netlink socket in the kernel module with NETLINK_GENERIC protocol type, netlink_kernel_create is called as follows:

.. code-block:: c

    struct sock* nlink

    nlink = netlink_kernel_create(NETLINK_GENERIC, receive_func);

    receive_func for example, is implemented as follows:

    void receive_func(struct sock *sock, int len)
    {
        struct sk_buff *buffer;
        struct nlmsghdr *nlh;

        while((buffer = skb_dequeue(&buffer->receive_queue)) != NULL)
        {
            nlh = (struct nlmsghdr *)buffer->data;

            //access the data through
            //NLMSG_DATA(nlh)
        }
    }

receive_func function is called in the sendmsg system call context. If the task that is to be done with the received message is small, then it can be done in receive_func; but if it is not small, then it can block other system calls and can cause delays in the application. So to avoid this, kernel threads can be later used to process the message. For this purpose, the skb_recv_datagram API can be used as follows:

.. code-block:: c

    struct sk_buff *buffer;
    int error;

    buffer = skb_recv_datagram(nlink, 0, 0, &error);

In the above code:
* nlink = struct sock* variable is returned by netlink_kernel_create.
* buffer = will be the buffer that will contain the Netlink message when the skb_recv_datagram wakes up.

After this call, the calling thread will block and will have to be woken up through wake_up_interruptible in receive_func callback as follows:

.. code-block:: c

    void receive_func(struct sock *buffer, int len)
    {
        // this will be wake up the thread
        //which has called skb_recv_datagram
        wake_up_interruptible(bufffer->sleep);
    }

After the thread has woken up, data can be accessed as follows:

.. code-block:: c

    struct sk_buff *buffer;
    int error;
    struct nlmsghdr *nlh;

    //here the thread will sleep till the message
    //is received, after message is received
    //receive_func is called which will wake
    //up this thread
    buffer = skb_recv_datagram(nlink, 0, 0, &error);

    //access the data through buffer variable
    nlh = (struct nlmsghdr *)buffer->data;

    //access the data through NLMSG_DATA macro
    //in kernel
    printk( "Message received %s\n", NLMSG_DATA(nlh));

To close the Netlink socket allocated, sock_release is called as follows:

.. code-block:: c

    sock_release(&nlink->socket);

where nlink is the struct sock * variable returned by netlink_kernel_create api.
For sending unicast and multicast messages from the kernel to the process, the following are the APIs:

.. code-block:: c

    //unicast message sending from kernel
    int netlink_unicast(struct sock *ssk, struct sk_buff * skb, u32 pid, int nonblock);

In the above code:

    ssk is the struct sock * returned by netlink_kernel_create.
    skb is the buffer which holds the message.
    pid is the ID or address of the process to which the message is to be sent.
    Nonblock is the variable to decide whether to block if the process is not present.

.. code-block:: c

    //multicast message sending from kernel
    int netlink_broadcast(struct sock *ssk, struct sk_buff *skb, u32 pid, u32 group, int allocation);

In the above code:

    group is the multicast group to which the message is to be sent. This is similar to the nl_groups field in the sockaddr_nl structure.
    allocation is GFP_ATOMIC if called from the interrupt context or GFP_KERNEL if called from the kernel thread. This is due to the fact that the kernel requires multiple buffer allocations to clone a multicast message.
    Let's end with an example of message sending in the kernel, as follows:

.. code-block:: c

    #define NLINK_MSG_SIZE 1024

    //allocate netlink socket
    struct sock *nlink = netlink_kernel_create(NETLINK_GENERIC, receive_func);

    //allocate socket buffer for message
    struct sk_buff *skb = alloc_skb(NLMSG_SPACE(NLINK_MSG_SIZE), GFP_KERNEL);

    //get the header pointer
    nlh = (struct nlmsghdr *) skb->data;

    //update source header parameters
    nlh->nlmsg_len = NLMSG_SPACE(NLINK_MSG_SIZE);

    //kernel id is 0
    nlh->nlmsg_pid = 0;

    nlh->nlmsg_flags = 0;

    //copy the data
    strcpy(NLMSG_DATA(nlh), "Hello");

    //update this if kernel belongs to
    //multicast group
    NETLINK_CB(skb).groups = 0;
    //kernel id is 0
    NETLINK_CB(skb).pid = 0;

    //use this in case of unicast message
    NETLINK_CB(skb).dst_pid = 2;

    //update this in case of multicast
    //message with multicast address
    NETLINK_CB(skb).dst_groups = 0;

    //unicast the message to process with
    //process address 2
    netlink_unicast(nlink, skb, 2, MSG_DONTWAIT);

    //use this if multicast is to be done
    //example is multicast address 3
    //netlink_broadcast(nlink, skb, 0, 1<<3, GFP_KERNEL);

References
==========

[1] http://qos.ittc.ku.edu/netlink/html/
[2] http://linux.die.net/man/7/netlink
