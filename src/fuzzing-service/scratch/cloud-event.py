import requests
from cloudevents.conversion import to_binary
from cloudevents.http import CloudEvent

# Create a CloudEvent
# - The CloudEvent "id" is generated if omitted. "specversion" defaults to "1.0".
attributes = {
    "type": "autopatch.crashdetail",
    "source": "autopatch.fuzzing-service",
}
data = {
    "crash_detail": "IW5ubm5uaGlvc2hYZGdmeVdBRkTCp8OpKsOnw6nDp0FMNMKwOyV4JXglbiVjUMJUJF49QSBGU1BPSiApPSLCo1U9VD9vamUgZmphbGRqIEFTREZQQ8OpSVFYWDs6IcKjPz1QNFjDJDEwOTM1MXMlcyV1OTAyNzVQNFjDoFdBRkTCp8OpKsOnw6nDp0FMU8KwOyV4JXgmbiVjUMKwS0ZEJgBSISlVVCRePUEgVlNQT0ogKT0ioqNVSwAEAABQbiBwb2pud2Vmbyt2a21vYyxhb3NmY2RwLipBKsKjUCI9JSEiRyQmPSEoJCkp",
    "executable_name": "complex2",
    "input_from_file": False,
}
event = CloudEvent(attributes, data)

# mqtt.publish("fuzzing-service/crashdetail", event)

# Creates the HTTP request representation of the CloudEvent in binary content mode
headers, body = to_binary(event)

# # POST
# requests.post("<some-url>", data=body, headers=headers)
