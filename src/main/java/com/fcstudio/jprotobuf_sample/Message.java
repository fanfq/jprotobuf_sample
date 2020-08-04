package com.fcstudio.jprotobuf_sample;

import com.baidu.bjf.remoting.protobuf.annotation.Protobuf;
import com.baidu.bjf.remoting.protobuf.annotation.ProtobufClass;
import lombok.Getter;
import lombok.Setter;

/**
 * @program: jprotobuf_sample
 * @description:
 * @author: fangqing.fan#hotmail.com
 * @create: 2020-07-31 22:23
 **/
@ProtobufClass
@Getter
@Setter
public class Message {

    @Protobuf(order = 2)
    private String name;

    @Protobuf(order = 1)
    private int value;



}
