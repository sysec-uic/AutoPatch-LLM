import logging
import time
import uuid
from typing import Callable, Dict, Final, Optional

import paho.mqtt.client as mqtt_client
import paho.mqtt.enums as mqtt_enums


class MessageBrokerClient:
    def __init__(
        self,
        message_broker_host: str,
        message_broker_port: int,
        logger: logging.Logger,
    ):
        self.message_broker_host = message_broker_host
        self.message_broker_port = message_broker_port
        self.topic_to_message_callback_map: Dict[str, Callable] = {}
        self.logger = logger
        _client = self.connect_message_broker()
        self.client = _client
        self.client.enable_logger(self.logger)
        self.client.loop_start()  # Start the network loop in a background thread to process callbacks.
        self.FIRST_RECONNECT_DELAY = 1
        self.RECONNECT_RATE = 2
        self.MAX_RECONNECT_COUNT = 12
        self.MAX_RECONNECT_DELAY = 60

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(host={self.message_broker_host}, port={self.message_broker_port})"

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message_broker_host={self.message_broker_host!r}, "
            f"message_broker_port={self.message_broker_port!r}"
            f")"
        )

    def connect_message_broker(self) -> mqtt_client.Client:

        def on_connect(client, userdata, flags, reason_code, properties) -> None:
            if reason_code == 0:
                self.logger.info(
                    f"{self.__class__.__name__} - Connected to MQTT Broker!"
                )
            else:
                self.logger.error(
                    f"{self.__class__.__name__} - Failed to connect to MQTT Broker!"
                )
                self.logger.debug(
                    f"{self.__class__.__name__} - Failed to connect, return code {reason_code}\n"
                )

        def on_disconnect(
            client, userdata, disconnect_flags, reason_code, properties
        ) -> None:
            self.logger.info(
                f"{self.__class__.__name__} - Disconnected with result code: {reason_code}"
            )
            reconnect_count, reconnect_delay = 0, self.FIRST_RECONNECT_DELAY
            while reconnect_count < self.MAX_RECONNECT_COUNT:
                self.logger.info(
                    f"{self.__class__.__name__} - Reconnecting in {reconnect_delay} seconds..."
                )
                time.sleep(reconnect_delay)

                try:
                    client.reconnect()
                    self.logger.info(
                        f"{self.__class__.__name__} - Reconnected successfully!"
                    )
                    return
                except Exception as err:
                    logging.error(
                        f"{self.__class__.__name__} - {err}. Reconnect failed. Retrying..."
                    )
                reconnect_delay *= self.RECONNECT_RATE
                reconnect_delay = min(reconnect_delay, self.MAX_RECONNECT_DELAY)
                reconnect_count += 1
            self.logger.info(
                f"{self.__class__.__name__} - Reconnect failed after {reconnect_count} attempts. Exiting..."
            )

        def on_publish(client, userdata, mid, reason_code, properties) -> None:
            self.logger.info(f"{self.__class__.__name__} - Message {mid} published")

        def on_message(client, userdata, message) -> None:
            self.logger.info(
                f"{self.__class__.__name__} - Message received on topic {message.topic}: {message.payload}"
            )
            self.logger.info("Message received on topic: " + message.topic)

            self.trigger_event(
                self.topic_to_message_callback_map.get(message.topic, None),
                message.payload.decode("utf-8"),
            )

        def generate_uuid() -> str:
            return str(uuid.uuid4())

        # Generate a Client ID with the publish prefix.
        client_id = f"publish-{generate_uuid()}"
        client = mqtt_client.Client(
            client_id=client_id,
            callback_api_version=mqtt_enums.CallbackAPIVersion.VERSION2,
        )
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_publish = on_publish
        client.on_message = on_message
        self.logger.info(
            f"{self.__class__.__name__} - Connecting to MQTT Broker on {self.message_broker_host}:{self.message_broker_port}"
        )
        client.connect(self.message_broker_host, self.message_broker_port)
        return client

    async def publish(self, topic: str, message: str) -> str:
        """
        Publish a message to the specified topic.
        """
        # at least once delivery, publish is non-blocking by default
        result: mqtt_client.MQTTMessageInfo = self.client.publish(topic, message, qos=1)
        if result.rc != mqtt_enums.MQTTErrorCode.MQTT_ERR_SUCCESS:
            self.logger.error(
                f"{self.__class__.__name__} - Failed to send message to topic {topic}"
            )
            return "Failed to send message"
        self.logger.info(
            f"{self.__class__.__name__} - Published message to topic {topic}"
        )
        return "Message sent successfully"

    def consume(self, topic: str, callback_function: Optional[Callable]) -> None:
        """
        Consume messages from the specified topic.

        The provided callback function will be called with the message payload as a string.
        """
        self.client.subscribe(topic)
        if callable(callback_function):
            self.logger.info(f"{self.__class__.__name__} - Subscribed to topic {topic}")
            self.logger.info(
                f"{self.__class__.__name__} - Setting callback function for topic {topic} to {callback_function.__name__}"
            )
            self.topic_to_message_callback_map[topic] = callback_function
        else:
            error_message: Final[str] = "Callback function must be callable"
            self.logger.error(error_message)
            raise ValueError(error_message)

    def trigger_event(self, message_callback: Optional[Callable], *args, **kwargs):
        if message_callback:
            return message_callback(*args, **kwargs)
        else:
            self.logger.info("No callback function set.")
