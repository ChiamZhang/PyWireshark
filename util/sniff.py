def get_packet_layers( packet):
    counter = 0

    while True:
        layer = packet.getlayer(counter)
        # print(layer)
        if layer is None:
            break
        yield layer
        counter += 1


