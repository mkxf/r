package com.ai.mqconsumer.service;

import java.io.UnsupportedEncodingException;
import java.util.List;

import com.ai.common.xml.util.ControlConstants;
import com.ai.frame.bean.InputObject;
import com.ai.frame.bean.OutputObject;
import com.ai.frame.logger.Logger;
import com.ai.frame.logger.LoggerFactory;
import com.ai.frame.util.JsonUtil;
import com.ai.mqconsumer.util.Constants.MQ_TOPIC;
import com.alibaba.rocketmq.client.consumer.DefaultMQPushConsumer;
import com.alibaba.rocketmq.client.consumer.listener.ConsumeConcurrentlyContext;
import com.alibaba.rocketmq.client.consumer.listener.ConsumeConcurrentlyStatus;
import com.alibaba.rocketmq.client.consumer.listener.MessageListenerConcurrently;
import com.alibaba.rocketmq.common.message.MessageExt;
/**
 * 秒杀实现类
 */
public class SeckillConsumerServiceImpl extends AbstractConsumerService {
    private Logger logger = LoggerFactory.getServiceLog(SeckillConsumerServiceImpl.class);
    @Override
    protected void consumeMessage() {
        logger.info("consumeMessage", "TOPIC_OPER_LOG_Consumer_Group消费组开始监听.....");
        try {
            DefaultMQPushConsumer consumer = super.getConsumer(MQ_TOPIC.TOPIC_MAMP_SECKILL);
            consumer.registerMessageListener(new MessageListenerConcurrently() {
                @Override
                public ConsumeConcurrentlyStatus consumeMessage(List<MessageExt> msgs,
                    ConsumeConcurrentlyContext context) {
                    String json=null;
                    try {
                        json = new String(msgs.get(0).getBody(),"utf-8");
                    } catch (UnsupportedEncodingException e1) {
                        e1.printStackTrace();
                    }
                    return doBusiness(json);
                }

                /**
                 * 业务逻辑
                 *
                 * @param msgContent
                 * @return
                 */
                public ConsumeConcurrentlyStatus doBusiness(String msgContent) {
                    /**
                     * consumerStatus默认必须返回成功，
                     * 只有因为业务逻辑的网络问题导致业务处理失败，才需要返回ConsumeConcurrentlyStatus.
                     * RECONSUME_LATER
                     */
                    ConsumeConcurrentlyStatus consumerStatus = ConsumeConcurrentlyStatus.CONSUME_SUCCESS;
                    /**
                     * 业务逻辑处理块必须加异常处理，必须写在try块中，且不能往外抛
                     */
                    try {
                        logger.info("consumeMessage", "TOPIC_MAMP_SECKILL消费消息:" + msgContent);
                        InputObject inputObject = JsonUtil.json2InputObject(msgContent);

                        OutputObject outputObject = getControlService().execute(inputObject);
                        // TODO 保存成功
                        if (ControlConstants.RETURN_CODE.IS_OK.equals(outputObject.getReturnCode())) {
                            logger.info("consumeMessage", "秒杀记录保存成功！");
                        }
                    } catch (Exception e) {
                        logger.error("TOPIC_MAMP_SECKILL消费异常！", "msgContent=" + msgContent, e);
                    }
                    return consumerStatus;
                }
            });
            consumer.start();
            logger.info("consumeMessage", "TOPIC_MAMP_SECKILL消费组启动监听成功!");
        } catch (Exception e) {
            logger.info("consumeMessage", "TOPIC_MAMP_SECKILL消费组启动监听失败!", e);
        }
    }
}
