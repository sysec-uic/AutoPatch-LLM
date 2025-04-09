import logging
from unittest import mock

import paho.mqtt.client as mqtt_client
import paho.mqtt.enums as mqtt_enums
import pytest
from autopatchpubsub import MessageBrokerClient


# Simulate a successful connect (returning 0)
def mock_connect(self, host, port) -> int:
    assert host == "localhost"
    assert port == 1883
    return 0


@pytest.fixture(autouse=True)
def mocked_logger() -> logging.Logger:
    return mock.Mock(spec=logging.Logger)


def test_str(monkeypatch, mocked_logger):
    monkeypatch.setattr(mqtt_client.Client, "connect", mock_connect)
    test_instance = MessageBrokerClient("localhost", 1883, mocked_logger)
    expected = "MessageBrokerClient(host=localhost, port=1883)"
    assert str(test_instance) == expected


def test_repr(monkeypatch, mocked_logger):
    monkeypatch.setattr(mqtt_client.Client, "connect", mock_connect)
    test_instance = MessageBrokerClient("localhost", 1883, mocked_logger)
    expected = (
        "MessageBrokerClient(message_broker_host='localhost', message_broker_port=1883)"
    )
    assert repr(test_instance) == expected


def test_connect_message_broker_success(monkeypatch, mocked_logger):
    monkeypatch.setattr(mqtt_client.Client, "connect", mock_connect)
    client = MessageBrokerClient("localhost", 1883, mocked_logger)
    # Assert that the client object was created and the connection log is written.
    assert client.client is not None
    mocked_logger.info.assert_called_with(
        "MessageBrokerClient - Connecting to MQTT Broker on localhost:1883"
    )


def test_connect_message_broker_failure(monkeypatch, mocked_logger):
    # Simulate a connection failure by raising an exception.
    def mock_connect_failure(self, host, port):
        raise Exception("Connection failed")

    monkeypatch.setattr(mqtt_client.Client, "connect", mock_connect_failure)
    with pytest.raises(Exception, match="Connection failed"):
        MessageBrokerClient("localhost", 1883, mocked_logger)
    mocked_logger.info.assert_called_with(
        "MessageBrokerClient - Connecting to MQTT Broker on localhost:1883"
    )


@pytest.mark.asyncio
async def test_publish_success(monkeypatch, mocked_logger):
    # Create a mock client and simulate a successful publish.
    mock_client = mock.Mock()
    mock_result = mock.Mock()
    mock_result.rc = mqtt_enums.MQTTErrorCode.MQTT_ERR_SUCCESS
    mock_client.publish.return_value = mock_result

    # Monkeypatch the Client class to return our mock client.
    monkeypatch.setattr(mqtt_client, "Client", lambda *args, **kwargs: mock_client)

    client = MessageBrokerClient("localhost", 1883, mocked_logger)
    # Override the internal client with our mock.
    client.client = mock_client
    await client.publish("test/topic", "test message")

    mock_client.publish.assert_called_with("test/topic", "test message", qos=1)
    mocked_logger.info.assert_any_call(
        "MessageBrokerClient - Published message to topic test/topic"
    )


@pytest.mark.asyncio
async def test_publish_failure(monkeypatch, mocked_logger):
    # Create a mock client that simulates a failed publish.
    mock_client = mock.Mock()
    mock_result = mock.Mock()
    mock_result.rc = mqtt_enums.MQTTErrorCode.MQTT_ERR_NO_CONN
    mock_client.publish.return_value = mock_result

    monkeypatch.setattr(mqtt_client, "Client", lambda *args, **kwargs: mock_client)

    client = MessageBrokerClient("localhost", 1883, mocked_logger)
    client.client = mock_client
    await client.publish("test/topic", "test message")

    mock_client.publish.assert_called_with("test/topic", "test message", qos=1)
    mocked_logger.error.assert_called_with(
        "MessageBrokerClient - Failed to send message to topic test/topic"
    )


def test_on_disconnect_reconnect(monkeypatch, mocked_logger):
    # Create a mock client that fails its first reconnect attempt then succeeds.
    mock_client = mock.Mock()
    mock_client.reconnect.side_effect = [Exception("Reconnect failed"), None]

    monkeypatch.setattr(mqtt_client, "Client", lambda *args, **kwargs: mock_client)

    client = MessageBrokerClient("localhost", 1883, mocked_logger)
    client.client = mock_client
    # Call on_disconnect with full required arguments: client, userdata, disconnect_flags, reason_code, properties.
    client.client.on_disconnect(client.client, None, None, 1, None)
    mocked_logger.info.assert_any_call(
        "MessageBrokerClient - Reconnecting in 1 seconds..."
    )
    mocked_logger.info.assert_any_call(
        "MessageBrokerClient - Reconnected successfully!"
    )


def test_generate_uuid(monkeypatch, mocked_logger):
    monkeypatch.setattr(mqtt_client.Client, "connect", mock_connect)
    # Define a fixed UUID for testing.
    mock_uuid = "123e4567-e89b-12d3-a456-426614174000"
    with mock.patch("uuid.uuid4", return_value=mock_uuid):
        client = MessageBrokerClient("localhost", 1883, mocked_logger)
        expected_id = f"publish-{mock_uuid}"
        assert client.client._client_id.decode() == expected_id


def test_on_message(monkeypatch, mocked_logger):
    monkeypatch.setattr(mqtt_client.Client, "connect", mock_connect)
    # Define a fixed UUID for testing.
    mock_uuid = "123e4567-e89b-12d3-a456-426614174000"
    with mock.patch("uuid.uuid4", return_value=mock_uuid):
        client = MessageBrokerClient("localhost", 1883, mocked_logger)
        expected_id = f"publish-{mock_uuid}"
        assert client.client._client_id.decode() == expected_id


@pytest.mark.asyncio
async def test_publish_with_empty_topic(monkeypatch, mocked_logger):
    """
    Edge case: Publishing with an empty topic.
    Instead of raising a ValueError, the publish method logs an error when publish fails.
    """
    mock_client = mock.Mock()
    mock_result = mock.Mock()
    # Simulate failure by returning a non-success result.
    mock_result.rc = mqtt_enums.MQTTErrorCode.MQTT_ERR_NO_CONN
    mock_client.publish.return_value = mock_result

    monkeypatch.setattr(mqtt_client, "Client", lambda *args, **kwargs: mock_client)
    client = MessageBrokerClient("localhost", 1883, mocked_logger)
    client.client = mock_client

    await client.publish("", "test message")

    mock_client.publish.assert_called_with("", "test message", qos=1)
    mocked_logger.error.assert_called_with(
        "MessageBrokerClient - Failed to send message to topic "
    )


def test_on_disconnect_no_reconnect(monkeypatch, mocked_logger):
    """
    Edge case: If reconnect fails continuously, the on_disconnect handler logs the failure after maximum attempts.
    This update monkeypatches time.sleep to avoid long delays during testing.
    """
    mock_client = mock.Mock()
    # Simulate reconnect always failing.
    mock_client.reconnect.side_effect = Exception("Reconnect failed")

    monkeypatch.setattr(mqtt_client, "Client", lambda *args, **kwargs: mock_client)
    # Patch time.sleep to skip actual waiting.
    monkeypatch.setattr("time.sleep", lambda seconds: None)

    client = MessageBrokerClient("localhost", 1883, mocked_logger)
    client.client = mock_client

    # Call on_disconnect with all required arguments.
    client.client.on_disconnect(client.client, None, None, 1, None)
    mocked_logger.info.assert_any_call(
        "MessageBrokerClient - Reconnecting in 1 seconds..."
    )
    mocked_logger.info.assert_any_call(
        "MessageBrokerClient - Reconnect failed after 12 attempts. Exiting..."
    )
