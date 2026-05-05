#include "netx_app.h"

/* NET packet pool struct */
static NX_PACKET_POOL    pool_0;

/* IpInterface struct */
static NX_IP             ip_0;

/* Net packet pool */
#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)
static UCHAR  packet_pool_area[NX_PACKET_POOL_SIZE];// __attribute__((section(".NetXPoolSection")));

/* Arp cache buffer */
#define	NX_ARP_POOL_SIZE		(1024)
static UCHAR  arp_space_area[NX_ARP_POOL_SIZE];// __attribute__((section(".NetXPoolSection")));

/* Tcp WND size */
#define	SOCKET_WND_SIZE			(32*1024)

/* error count */
ULONG error_count=0;

/* Defaule ip mask */
#define IP_ADDR0	(192)
#define	IP_ADDR1	(168)
#define IP_ADDR2	(3)
#define IP_ADDR3	(100)
#define	NET_IP_DEFAULT	IP_ADDRESS(IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3)
#define	NET_MASK		(0xFFFFFF00UL)

/* netx ip thread stack and priority */
#define  THREAD_NETX_IP0_PRIO0                          1u
#define  THREAD_NETX_IP0_STK_SIZE                     	(1024*8u)
static  UCHAR  thread_netx_ip0_stack[THREAD_NETX_IP0_STK_SIZE];

/* netx bsd stack */
//#define	THREAD_NETX_BSD_PRIO														2U
//#define	THREAD_NETX_BSD_STACK_SIZE											(1024*2u)
//static UCHAR	thread_netx_bsd_stack[THREAD_NETX_BSD_STACK_SIZE];

/* netx tcp initialization task stack and handle */
#define THREAD_TCP_STACK_SIZE		(1024u * 2)
#define THREAD_TCP_PRIO					(5u)
static TX_THREAD thread_tcp_block;
static UCHAR thread_tcp_block_stack[THREAD_TCP_STACK_SIZE];
static void thread_tcp_entry(ULONG thread_input);

/**
 * @brief NetX initialization
 */
UINT MX_NetXDuo_Init(void)
{
	ULONG status = 0;
	UINT nx_init_status = 0;
	
	/* Initialize the NetXDuo system. */
	nx_system_initialize();
	
	/* Create NetXDuo Packet Pool */
	nx_init_status |= nx_packet_pool_create(&pool_0,
									"NetX Main Packet Pool",
									(1536 + sizeof(NX_PACKET)),  packet_pool_area ,
									NX_PACKET_POOL_SIZE);
	
	/* Create NetXDuo Ip thread */
	nx_init_status |= nx_ip_create(&ip_0,
						"NetX IP0",
						NET_IP_DEFAULT,
						NET_MASK,
						&pool_0, nx_stm32_eth_driver,
						(UCHAR*)thread_netx_ip0_stack,
						sizeof(thread_netx_ip0_stack),
						THREAD_NETX_IP0_PRIO0);
						
	/* Enable Arp */
	nx_init_status |= nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));

	/* Enable subcontracting */
	nx_init_status |= nx_ip_fragment_enable(&ip_0);
						
	/* Enable Tcp */
	nx_init_status |= nx_tcp_enable(&ip_0);
	
	/* Enable Udp */
	nx_init_status |= nx_udp_enable(&ip_0);
	
	/* Enable ICMP */
	nx_init_status |= nx_icmp_enable(&ip_0);
						
	/* Set Default Gateway */	
	ULONG gateway_ip = NET_IP_DEFAULT;
	gateway_ip = (gateway_ip & NET_MASK) | 0x01;
	nx_ip_gateway_address_set(&ip_0, gateway_ip);		
	
	status = tx_thread_create(&thread_tcp_block, 
		"tx_init", 
		thread_tcp_entry, 
		0, 
		&thread_tcp_block_stack[0],
		THREAD_TCP_STACK_SIZE, 
		THREAD_TCP_PRIO, 
		THREAD_TCP_PRIO, 
		TX_NO_TIME_SLICE, 
		TX_AUTO_START);


//	if(status != TX_SUCCESS)
//		return status;
	
	return nx_init_status;
}

//#define	IPERF_BUFFER_SIZE	(4096)
//static UCHAR test_buffer[IPERF_BUFFER_SIZE];
static void thread_tcp_entry(ULONG thread_input)
{
	#define	TCP_SERVER_PORT	(5001)
	UINT status;
	NX_TCP_SOCKET tcp_socket;
	ULONG packet_size;
	NX_PACKET *packet;
#if NETX_TCP_USE_CLIENT
	ULONG bytes_read;
	ULONG recv_bytes = 0;
  /* Create TCP Socket */
  status = nx_tcp_socket_create(&ip_0, &tcp_socket, "TCP Server Socket", 
                                 NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 
                                 SOCKET_WND_SIZE, NX_NULL, NX_NULL);
	if(status != NX_SUCCESS)
	{
		return;
	}
	
	status = nx_tcp_server_socket_listen(&ip_0, TCP_SERVER_PORT, &tcp_socket, 5, NULL);
	if(status != NX_SUCCESS)
	{
		nx_tcp_socket_delete(&tcp_socket);
		return;
	}
	
  /* Accept the new client connection before starting data exchange */
  status = nx_tcp_server_socket_accept(&tcp_socket, NX_WAIT_FOREVER);

  if (status != NX_SUCCESS)
  {
		nx_tcp_socket_delete(&tcp_socket);
		return;
  }
	
	while(1)
	{
		ULONG socket_state;
		recv_bytes = 0;
		
		
		if(status == NX_SUCCESS)
		{
			status = nx_tcp_socket_receive(&tcp_socket, &packet, NX_WAIT_FOREVER);
			if(status == NX_SUCCESS)
			{
				/* Retrieve the data sent by the client */
//        nx_packet_data_retrieve(recv_packet, SOCKET_BUFFER_START, &recv_bytes);
				
				nx_packet_release(packet);
			}
      else
      {
        nx_tcp_socket_disconnect(&tcp_socket, NX_WAIT_FOREVER);
        nx_tcp_server_socket_unaccept(&tcp_socket);
        nx_tcp_server_socket_relisten(&ip_0, TCP_SERVER_PORT, &tcp_socket);
				nx_tcp_socket_delete(&tcp_socket);
				break;
      }
		}
	}
		
#else
	ULONG remaining_size = 0;
	UCHAR first = 0;
	#define	TCP_SERVER_IP		IP_ADDRESS(192,168,3,56)
	NXD_ADDRESS server_ip;
	NX_PACKET *new_packet = NULL;
	NX_PACKET *last_packet = NULL;
	server_ip.nxd_ip_version = NX_IP_VERSION_V4;
	server_ip.nxd_ip_address.v4 = TCP_SERVER_IP;
  status = nx_tcp_socket_create(&ip_0, &tcp_socket, "TCP Socket", 
                                 NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 
                                 SOCKET_WND_SIZE, NX_NULL, NX_NULL);
	
	if(status != NX_SUCCESS)
	{
		return;
	}
	
	tx_thread_sleep(2000);
	
	status =  nx_tcp_client_socket_bind(&tcp_socket, NX_ANY_PORT, NX_WAIT_FOREVER);
	if(status != NX_SUCCESS)
	{
		return;
	}
	

	status = nxd_tcp_client_socket_connect(&tcp_socket, &server_ip, TCP_SERVER_PORT, NX_WAIT_FOREVER);
	if(status != NX_SUCCESS)
	{
		nx_tcp_client_socket_unbind(&tcp_socket);
		return;
	}
	
	status = nx_tcp_socket_mss_get(&tcp_socket, &packet_size);
	if(status != NX_SUCCESS)
	{
		nx_tcp_socket_disconnect(&tcp_socket, NX_NO_WAIT);
		nx_tcp_client_socket_unbind(&tcp_socket);
		return;
	}
	
	while(1)
	{
		status = nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
		if(status != NX_SUCCESS)
		{
			break;
		}
		
		if (packet -> nx_packet_prepend_ptr + packet_size <= packet -> nx_packet_data_end)
		{
			packet->nx_packet_append_ptr = packet->nx_packet_prepend_ptr + packet_size;
			remaining_size = 0;
		}
		else
		{
			packet->nx_packet_append_ptr = packet->nx_packet_data_end;
			remaining_size = packet_size - ((ULONG)(packet->nx_packet_append_ptr - packet->nx_packet_prepend_ptr));
			last_packet = packet;
		}
		packet->nx_packet_length = packet_size;
		
		while(remaining_size)
		{
			status = nx_packet_allocate(&pool_0, &new_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
			if(status != NX_SUCCESS)
				goto __exit;
			
			last_packet->nx_packet_next = new_packet;
			last_packet = new_packet;
			if(remaining_size < (ULONG)(new_packet->nx_packet_data_end - new_packet->nx_packet_prepend_ptr))
			{
				new_packet->nx_packet_append_ptr =  new_packet->nx_packet_prepend_ptr + remaining_size;
			}
			else
			{
				new_packet->nx_packet_append_ptr =  new_packet->nx_packet_data_end;
			}
			remaining_size = remaining_size - (ULONG)(new_packet->nx_packet_append_ptr - new_packet->nx_packet_prepend_ptr);
		}
		
		if(!first)
		{
			first = 1;
			memset(packet->nx_packet_prepend_ptr, 0, (UINT)(packet->nx_packet_data_end - packet->nx_packet_prepend_ptr));
		}
		
		status = nx_tcp_socket_send(&tcp_socket, packet, NX_WAIT_FOREVER);
	
		if(status != NX_SUCCESS)
		{
			nx_packet_release(packet);
			break;
		}
	}
	
	__exit:
	nx_tcp_socket_disconnect(&tcp_socket, NX_NO_WAIT);
	nx_tcp_client_socket_unbind(&tcp_socket);
	nx_tcp_socket_delete(&tcp_socket);
#endif	
}
