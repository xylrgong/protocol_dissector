# protocol_dissector

#### 项目说明
protocol_dissector是工控协议解析与回放系统的编码实现
项目主要目录包括：
	automata   各类协议自动机
	protocols  协议解析构造插件
	proxy      被动协议栈
	tests      测试脚本
	utils      工具类及工具函数
工程运行入口位于根目录的main.py文件

#### 田湾协议回放测试说明
	田湾最小系统中实现的协议回放是S5协议的回放攻击
	S5协议是ES工程师站与AP控制器之间的通信协议
	此协议目前支持AP阀门设备的启停，和AP控制器的启停
	
	S5协议的测试脚本在文件tests/test_s5.py中，可使用以下测试步骤：
	1. 修改tests/tests.py文件的run()函数，在其中调用TestS5().test()
	2. 修改tests/test_s5.py文件的test()函数，在其中调用测试函数
	3. 修改tests/test_s5.py文件中的变量 TEST_IFACE，将其修改为本机使用的网络接口名
	4. 运行path_to_project/main.py，可在控制台运行，也可在IDE中运行
	5. 如果需要本地测试（即：使用本地运行的S5服务端）
	   可在运行main.py前，先在另一个命令行窗口运行path_to_project/test.py，开启S5服务端

#### 方家山协议回放测试说明
	方家山系统实现的协议回放攻击，包括：
		1) OWP-SAR/STR段，测试主机连接到SAR/STR服务器
		2) L1CFR-AW段，测试主机连接到AW服务器
		3) SAS-CCT段，测试主机连接到CCT服务器
		
	这三段通信的回放攻击脚本在文件tests/test_fangjiashan.py中，可使用以下测试步骤：
	1. 修改本机IP配置，使本机与目标服务器位于同一网段
	2. 修改tests/tests.py文件的run()函数，在其中调用TestFangJiaShan().test()
	3. 修改tests/test_fangjiashan.py文件的test()函数，在其中调用测试函数
	4. 运行path_to_project/main.py，可在控制台运行，也可在IDE中运行
	