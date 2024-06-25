
sink_categories = {

    "topic": ["getTopic", "topic", "topicFilter", "setWillTopic",
                "subscribe", "<io.netty.handler.codec.mqtt.MqttSubscribePayload: void <init>(java.util.List)>", "subscribeToTopic",
                "publish", "<io.netty.handler.codec.mqtt.MqttPublishVariableHeader: void <init>(java.lang.String,int)>", "publishData", "publishString"],

    "username": ["setUserName", "username", "setClientId"],
    "password": ["setPassword", "password"],

    "payload": ["<com.tuya.smart.mqttclient.mqttv3.MqttMessage: void <init>(byte[])>", "setPayload", "ChannelFuture write(", "<io.netty.handler.codec.mqtt.MqttPublishMessage: void <init>", "payload"],

    "server": ["<init>", "setServerURIs", "getClient", "setClientIdentifier", "ChannelFuture connect(", "connect", 
               "setHost", "serverAddress", "serverHost", "setHost", "setLocalAddress"],

    "port": ["setPort", "serverPort"],
}

# multiple is where you can find more than one field in the same string (e.g. first signature of multiple corresponds to clientHandle = serveruri + ":" + clientid + ":" + contextID)
sink_cats = {
    "client": 
    [
        ("getClient(", '1'), 
        ("MqttAndroidClient: void <init>", '2'),
        ("MqttClient: void <init>(", '1'),
        ("MqttAsyncClient: void <init>(", '1'),
        ("setClientIdentifier(", '0'),
        ("MqttClientBuilderBase identifier", '0'),
        ("setClientId(", '0'),
        ("AWSIotMqttManager: void <init>(", '0')

    ],

    "server": 
    [
        ("getClient(", '0'), 
        ("MqttAndroidClient: void <init>", '1'),
        ("setServerURIs(", '0'),
        ("MqttClient: void <init>(", '0'),
        ("MqttAsyncClient: void <init>(", '0'),
        ("setHost(", '0'),
        ("serverHost(", '0'),
        ("serverAddress(", '0'),
        ("setLocalAddress(", '0'),
        ("AWSIotMqttManager: void <init>(", '1'),

    ],

    "topic": 
    [
        ("MqttService: org.eclipse.paho.client.mqttv3.IMqttDeliveryToken publish(", '1'), 
        ("MqttAndroidClient: org.eclipse.paho.client.mqttv3.IMqttDeliveryToken publish(", '0'),
        ("MqttService: void subscribe(", '1'),
        ("IMqttToken subscribe(", '0'),
        ("paho.client.mqttv3.MqttClient: void publish(", '0'),
        ("mqttv3.MqttClient: void subscribe(", '0'),
        ("IMqttClient: void publish(", '0'),
        ("IMqttClient: void subscribe(", '0'),
        ("mqttv5.client.MqttClient: void publish(", '0'),
        ("mqttv5.client.MqttClient: void subscribe(", '0'),
        ("mqtt.MqttClient: void publish(", '0'),
        ("mqtt.MqttClient: void subscribe(java.lang.String[])", '0'),
        ("mqtt.MqttClient: void subscribe(int,java.lang.String[])", '1'),
        ("MqttPublishVariableHeader: void <init>", '0'),
        ("MqttSubscribePayload: void <init>",'0'),
        ("topic(", '0'),
        ("Topic(", '0'),
        ("void publish(java.lang.String,com.tuya.smart.mqttclient.mqttv3.MqttMessage)", '0'),
        ("com.tuya.smart.mqttclient.mqttv3.MqttClient: void publish(java.lang.String,byte[],int,boolean)", '0'),
        ("subscribeWithResponse", '0'),
        ("topicFilter(", '0'),
        ("BlockingConnection: void publish(", '0'),
        ("org.fusesource.mqtt.client.Future publish(", '0'),
        ("org.fusesource.mqtt.client.Future subscribe(", '0'),
        ("MqttService: void subscribe(", '0'),
        ("publishData(byte[],java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos)", '1'),
        ("publishData(byte[],java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos,com.amazonaws.mobileconnectors.iot.AWSIotMqttMessageDeliveryCallback,java.lang.Object)", '1'),
        ("publishString(java.lang.String,java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos)", '1'),
        ("publishString(java.lang.String,java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos,com.amazonaws.mobileconnectors.iot.AWSIotMqttMessageDeliveryCallback,java.lang.Object)", '1'),
        ("subscribeToTopic(", '0'),

    ],

    "payload": 
    [
        ("MqttService: org.eclipse.paho.client.mqttv3.IMqttDeliveryToken publish(", '2'),
        ("MqttAndroidClient: org.eclipse.paho.client.mqttv3.IMqttDeliveryToken publish(", '1'),
        ("paho.client.mqttv3.MqttClient: void publish(", '1'),
        ("IMqttClient: void publish(", '1'),
        ("mqttv5.client.MqttClient: void publish(", '1'),
        ("mqtt.MqttClient: void publish(", '1'),
        ("io.netty.channel.ChannelFuture write(", '0'),
        ("MqttPublishMessage: void <init>", '2'),
        ("MqttMessage: void", '0'),
        ("com.tuya.smart.mqttclient.mqttv3.MqttClient: void publish(java.lang.String,byte[],int,boolean)", '1'),
        ("payload(", '0'),
        ("BlockingConnection: void publish(", '1'),
        ("org.fusesource.mqtt.client.Future publish(", '1'),
        ("publishData(byte[],java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos)", '0'),
        ("publishData(byte[],java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos,com.amazonaws.mobileconnectors.iot.AWSIotMqttMessageDeliveryCallback,java.lang.Object)", '0'),
        ("publishString(java.lang.String,java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos)", '0'),
        ("publishString(java.lang.String,java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos,com.amazonaws.mobileconnectors.iot.AWSIotMqttMessageDeliveryCallback,java.lang.Object)", '0'),
    ],

    "username":
    [
        ("UserName(", '0'),
        ("username(", '0'),
    ],

    "password":
    [
        ("Password(", '0'),
        ("password(", '0'),
    ],

    "port":
    [
        ("setPort", '0'),
        ("serverPort(", '0'),
        ("org.fusesource.mqtt.client.MQTT: void setHost(", '1'),
    ],

    "multiple": 
    [
        ("MqttService: org.eclipse.paho.client.mqttv3.IMqttDeliveryToken publish(", '0'),
        ("io.netty.channel.ChannelFuture connect(", '0'),
        ("publishData(byte[],java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos,com.amazonaws.mobileconnectors.iot.AWSIotMqttMessageDeliveryCallback,java.lang.Object)", '4'),
        ("publishString(java.lang.String,java.lang.String,com.amazonaws.mobileconnectors.iot.AWSIotMqttQos,com.amazonaws.mobileconnectors.iot.AWSIotMqttMessageDeliveryCallback,java.lang.Object)", '4'),
    ],
}