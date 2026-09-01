from collections import Counter


def protocol_distribution(events):
    return Counter(
        event.protocol
        for event in events
        if event.protocol
    )


def priority_distribution(events):
    return Counter(
        event.priority
        for event in events
        if event.priority is not None
    )


def sid_distribution(events):
    return Counter(
        event.sid
        for event in events
        if event.sid is not None
    )


def signature_distribution(events):
    return Counter(
        event.signature
        for event in events
        if event.signature
    )


def action_distribution(events):
    return Counter(
        event.action
        for event in events
        if event.action
    )


def source_distribution(events):
    return Counter(
        event.src_ip
        for event in events
        if event.src_ip
    )


def destination_distribution(events):
    return Counter(
        event.dst_ip
        for event in events
        if event.dst_ip
    )


def port_distribution(events):
    return Counter(
        event.dst_port
        for event in events
        if event.dst_port is not None
    )


def summary(events):
    return {
        "total": len(events),
        "unique_sids": len(
            {
                event.sid
                for event in events
                if event.sid is not None
            }
        ),
        "protocols": protocol_distribution(events),
        "priorities": priority_distribution(events),
        "sids": sid_distribution(events),
        "signatures": signature_distribution(events),
        "actions": action_distribution(events),
        "sources": source_distribution(events),
        "destinations": destination_distribution(events),
        "ports": port_distribution(events),
    }
