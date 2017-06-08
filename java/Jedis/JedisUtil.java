package com.ai.mampbusi.util;

import java.util.HashSet;
import java.util.Set;

import com.ai.mampbusi.util.Constants.SYSTEM_PROP_CONFIG;

import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.JedisCluster;

public class JedisUtil {
	private static Set<HostAndPort> jedisClusterNodes = new HashSet<HostAndPort>();
	private static JedisCluster jedisCluster = null;
	
	static {
		try {
			jedisCluster = reloadJedisCluster();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 获取JedisCluster对象
	 * @return
	 * @throws Exception
	 */
	public static JedisCluster getCluster() throws Exception {
		if (jedisCluster == null) {
			synchronized (JedisUtil.class) {
				jedisCluster = reloadJedisCluster();
			}
		}
		return jedisCluster;
	}
	
	public static JedisCluster reloadJedisCluster() throws Exception {
		System.out.println("初始化实体");
		
		JedisCluster cluster = null;
		String redisAddrCfg = PropertiesUtil.getString(SYSTEM_PROP_CONFIG.REDIS_ADDR_CFG);
		if (StringUtil.isEmpty(redisAddrCfg) || redisAddrCfg.split(SYSTEM_PROP_CONFIG.REDIS_CFG_SPLIT).length == 0) {
			throw new Exception("System.properties中REDIS_ADDR_CFG属性为空");
		}
		String[] addrs = redisAddrCfg.split(SYSTEM_PROP_CONFIG.REDIS_CFG_SPLIT);
		for (String addr : addrs) {
			String[] ipAndPort = addr.split(":");
			if (ipAndPort == null || ipAndPort.length != 2 || !StringUtil.isNum(ipAndPort[1])) {
				throw new Exception("System.properties中REDIS_ADDR_CFG属性配置错误");
			}
			jedisClusterNodes.add(new HostAndPort(ipAndPort[0], Integer.parseInt(ipAndPort[1])));
		}
		cluster = new JedisCluster(jedisClusterNodes, 2000 , 6);
		return cluster;
	}
	
	public static void main(String[] args) throws Exception {
		for (int i = 0; i < 100000; i++) {
			new Thread(
				new Runnable() {
					public void run() {
						try {
							for (int j = 0; j < 10; j++) {
							 long id = getCluster().incr("nihaoa");
							 System.out.println(Thread.currentThread().getName() + " " + id);
							}
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				}
			,""+i).start();
			
		}
}
}
