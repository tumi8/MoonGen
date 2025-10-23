local mg                  = require "moongen"
local memory              = require "memory"
local device              = require "device"
local ts                  = require "timestamping"
local stats               = require "stats"
local hist                = require "histogram"
local pipe                = require "pipe"
local launch_timestamp    = require "launch-timestamp"
local ffi                 = require "ffi"
local log                 = require "log"
local dpdkc               = require "dpdkc"

function configure(parser)
	parser:description("Path property emulation (delay, packet loss, rate).")
	
	-- Port settings
	parser:argument("dev1", "Device to transmit/receive from."):convert(tonumber)
	parser:argument("dev2", "Device to transmit/receive from."):convert(tonumber)
	
	-- Path property settings
	parser:option("-d --delay", "Delay to introduce, while forwarding (in ms)."):default(0):convert(tonumber)
	parser:option("-r --rate", "Rate limit (in Mbps)."):default(0):convert(tonumber)	
	parser:option("-l --loss", "Packet loss (in %)."):default(0):convert(tonumber)
	parser:option("-g --ge-loss", "Packet loss parameters for Gilbert-Elliot model (p [r [1-h [1-k]]])."):args("+"):convert(tonumber)
	parser:option("-n --netem-loss", "Packet loss parameters for NetEm model (p13,p31,p32,p23,p14)."):args("+"):convert(tonumber)

	-- Invalid packet based Latency
	parser:flag("--hardware", "Using interspersed invalid packets to achive high precision latency emulation")

	-- Rate Limiting options
	parser:flag("--leaky-bucket", "Use leaky bucket shaper for rate limiting")
	parser:option("-c --capacity", "Capacity of buffer to keep for rate limiting (in B)"):default(32768):convert(tonumber)

	-- Misc Settings
	parser:option("--buffer-size", "Amount of memory to use for buffering packets per direction (in GB)"):default(0):convert(tonumber)
	parser:option("--seed", "Seed for the random number generator used for packet loss"):default(12345):convert(tonumber)
	parser:option("-t --threads", "Number of threads to use per direction. Cannot be used when using hardware delay functionality!"):default(1):convert(tonumber)
	parser:flag("-u --unidirectional", "Only forward traffic in one direction (from dev1 to dev2)")
	parser:flag("--stats", "Show stats output")
end

ffi.cdef[[
	enum loss_type {
		NONE,
		UNIFORM,
		GE,
		NETEM
	};

	struct moonem_config {
		uint64_t delay;
		uint64_t rate;
		uint64_t capacity;
		uint64_t loss_seed;
		enum loss_type loss_type;
		uint64_t loss;
		uint64_t loss_model_parameters[8];
	};

	void receiver_loop_delay(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config);
	void receiver_loop_rate_leaky_bucket(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config);
	void receiver_loop_rate_token_bucket_fwd(int port_id_rx, int queue_id_rx, int port_id_tx, int queue_id_tx, struct moonem_config config);
	void receiver_loop_rate_token_bucket(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config);
	
	void init_dynfield_burst_size_offset();
	void sw_receiver_loop_fwd(int port_id_rx, int queue_id_rx, int port_id_tx, int queue_id_tx, struct moonem_config config);
	void sw_receiver_loop_delay(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config);
	void sw_receiver_loop_rate_token_bucket(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config);
	void sw_receiver_loop_rate_leaky_bucket(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config);
	void sw_transmitter_loop_delay(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config);
]]

function scale_to_uint64(val)
	if val == 1 then
		return ffi.new("uint64_t", 0xFFFFFFFFFFFFFFFFULL)
	else
		return ffi.new("uint64_t", 2^64 * val)
	end
end

function master(args)
	if args.hardware and args.delay == 0 and args.leaky_bucket then
		log:fatal("Hardware based leaky bucket rate limiting is only possible, when delay is activated!")
	end
	
	if args.hardware and args.delay ~= 0 and args.threads > 1 then
		log:fatal("Only one thread can be used, when hardware based delay is activated!")
	end

	if ((args.loss > 0 and 1 or 0) + (args.ge_loss and 1 or 0) + (args.netem_loss and 1 or 0) > 1) then
		log:fatal("Only one loss model type can be specified simultaneously!")
	end

	args.delay = args.delay * 1000000
	args.rate = args.rate / args.threads
	args.config_struct = ffi.new("struct moonem_config",{
		delay = args.delay,
		rate = args.rate,
		capacity = args.capacity,
		loss_seed = args.seed,
	})

	-- perpare loss parameters depending on the configured loss model
	local loss_type
	if args.loss > 0 then
		loss_type = ffi.C.UNIFORM
		args.config_struct.loss = scale_to_uint64(args.loss / 100)
	elseif args.ge_loss then
		loss_type = ffi.C.GE

		local parameter_count = #args.ge_loss
		if parameter_count < 1 then
			args.ge_loss[1] = 0;
		end
		if parameter_count < 2 then
			args.ge_loss[2] = 100 - args.ge_loss[1];
		end
		if parameter_count < 3 then
			args.ge_loss[3] = 100;
		end
		if parameter_count < 4 then
			args.ge_loss[4] = 0;
		end

		for i = 1,#args.ge_loss do
			args.config_struct.loss_model_parameters[i-1] = scale_to_uint64(args.ge_loss[i] / 100)
		end
	elseif args.netem_loss then
		loss_type = ffi.C.NETEM

		if #args.netem_loss ~= 5 then
			log:fatal("All five netem loss model parameters are required!")
		end

		for i = 1,#args.netem_loss do
			if args.netem_loss[i] < 0 or args.netem_loss[i] > 100 then
				log:fatal("All netem loss model parameters need to be in [0, 100]")
			end
		end

		local p13 = 1
		local p31 = 2
		local p32 = 3
		local p23 = 4
		local p14 = 5

		local new_args = {}
		new_args[1] = 100 - args.netem_loss[p13] - args.netem_loss[p14]
		new_args[2] = 100 - args.netem_loss[p14]
		
		new_args[3] = 100 - args.netem_loss[p23];
		new_args[4] = args.netem_loss[p23];
		
		new_args[5] = 100 - args.netem_loss[p31] - args.netem_loss[p32];
		new_args[6] = args.netem_loss[p32];

		new_args[7] = 0;
		new_args[8] = 100;

		for i = 1,#new_args do
			args.config_struct.loss_model_parameters[i-1] = scale_to_uint64(new_args[i]/100)
		end
	else
		loss_type = ffi.C.NONE
	end
	args.config_struct.loss_type = loss_type

	if args.dev1 == args.dev2 then
		args.unidirectional = true
	end

	-- register dynfield for software burst optimization
	if not args.hardware then
		ffi.C.init_dynfield_burst_size_offset()
	end
	
	-- determine buffer size for keeping delayed packets (default 256k packets)
	local buf_count = 262144
	if args.buffer_size ~= 0 then
		buf_count = args.buffer_size * 1000000000 / 2048		
	end

	local buf_count_dev1, buf_count_dev2
	if args.unidirectional then
		buf_count_dev1 = buf_count
		buf_count_dev2 = nil
	else
		buf_count_dev1 = buf_count / 2
		buf_count_dev2 = buf_count / 2
	end

	-- larger descriptor ring sizes increase performance for hardware based latency emulation
	local descriptorCount = 512
	if args.hardware then
		descriptorCount = 2048
	end

	-- initialize ports
	local dev1 = device.config({port = args.dev1, rxQueues = args.threads, txQueues = args.threads, txDescs = descriptorCount, rxDescs = descriptorCount, numBufs = buf_count_dev1, rssQueues = args.threads})
	local dev2 = device.config({port = args.dev2, rxQueues = args.threads, txQueues = args.threads, txDescs = descriptorCount, rxDescs = descriptorCount, numBufs = buf_count_dev2, rssQueues = args.threads})
	device.waitForLinks()

	-- start temperature recording
	mg.startTask("tempSlave", dev1)
	if args.dev1 ~= args.dev2 then
		mg.startTask("tempSlave", dev2)
	end

	-- initialize timestamping when using hardware based latency emulation
	if args.hardware then
		dev1:enableRxTimestampsAllPackets()
		dev2:enableRxTimestampsAllPackets()
	end

	-- enable stats (might increase worst case delay variations)
	if args.stats then
		stats.startStatsTask{dev1, dev2}
	end

	-- use software implementation if only loss is selected
	if args.delay == 0 and args.rate == 0 then
		args.hardware = false
	end

	-- no transmit thread required for software implementations
	if not args.hardware and args.delay == 0 and args.rate == 0 then
		for i=0,args.threads-1 do
			mg.startTask("sw_rx_loop", dev1:getRxQueue(i), nil, args, dev2:getTxQueue(i), dev1)
			if not args.unidirectional then
				mg.startTask("sw_rx_loop", dev2:getRxQueue(i), nil, args, dev1:getTxQueue(i), dev2)
			end
		end
		return
	end

	-- no transmit thread required for hardware implementations
	if args.hardware and args.delay == 0 then
		for i=0,args.threads-1 do
			mg.startTask("hw_rx_loop", dev1:getRxQueue(i), nil, args, dev2:getTxQueue(i), dev1)
			if not args.unidirectional then
				mg.startTask("hw_rx_loop", dev2:getRxQueue(i), nil, args, dev1:getTxQueue(i), dev2)
			end
		end
		return
	end

	-- start hardware transmitters and receivers
	if args.hardware then
		local timer1 = launch_timestamp.new(dev2:getTxQueue(0), buf_count_dev1)
		timer1:start()
		mg.startTask("hw_rx_loop", dev1:getRxQueue(0), timer1.packet_ring, args, nil, dev1)

		if not args.unidirectional then
			local timer2 = launch_timestamp.new(dev1:getTxQueue(0), buf_count_dev2)
			timer2:start()
			mg.startTask("hw_rx_loop", dev2:getRxQueue(0), timer2.packet_ring, args, nil, dev2)
		end

		return
	end

	-- start software based transmitters and receivers
	for i=0,args.threads-1 do
		local packet_ring_1 = pipe:newPacketRing(buf_count_dev1)
		mg.startTask("sw_rx_loop", dev1:getRxQueue(i), packet_ring_1, args, nil, dev1)
		mg.startTask("sw_tx_loop", dev2:getRxQueue(i), packet_ring_1, args, nil, dev2)
		if not args.unidirectional then
			local packet_ring_2 = pipe:newPacketRing(buf_count_dev2)
			mg.startTask("sw_rx_loop", dev2:getRxQueue(i), packet_ring_2, args, nil, dev2)
			mg.startTask("sw_tx_loop", dev1:getRxQueue(i), packet_ring_2, args, nil, dev1)
		end
	end

	-- dont wait for threads to stop -> not having luajit running in this thread reduces prbability of TLB shootdowns
end

function hw_rx_loop(queue, packet_ring, args, txQueue)
	if args.delay == 0 then
		ffi.C.receiver_loop_rate_token_bucket_fwd(queue.dev.id, queue.qid, txQueue.dev.id, txQueue.qid, args.config_struct[0])
		return
	end

	-- delay is activated
	local rx_function
	if args.rate == 0 then
		rx_function = ffi.C.receiver_loop_delay
	elseif args.leaky_bucket then 
		rx_function = ffi.C.receiver_loop_rate_leaky_bucket
	else
		rx_function = ffi.C.receiver_loop_rate_token_bucket
	end

	rx_function(queue.dev.id, queue.qid, packet_ring.ring, args.config_struct[0])
end

function sw_rx_loop(queue, packet_ring, args, txQueue)
	if args.delay == 0 and args.rate == 0 then
		ffi.C.sw_receiver_loop_fwd(queue.dev.id, queue.qid, txQueue.dev.id, txQueue.qid, args.config_struct[0])
		return
	end

	local rx_function
	if args.rate == 0 then
		rx_function = ffi.C.sw_receiver_loop_delay
	elseif args.leaky_bucket then 
		rx_function = ffi.C.sw_receiver_loop_rate_leaky_bucket
	else
		rx_function = ffi.C.sw_receiver_loop_rate_token_bucket
	end

	rx_function(queue.dev.id, queue.qid, packet_ring.ring, args.config_struct[0])
end

function sw_tx_loop(queue, packet_ring, args, txQueue)
	ffi.C.sw_transmitter_loop_delay(queue.dev.id, queue.qid, packet_ring.ring, args.config_struct[0])
end

function tempSlave(dev)
	dpdkc.record_temperature(dev.id)
end
