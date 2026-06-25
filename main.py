from helpers.ospf_spoofer import (
        OSPFSession,
        OSPFConfig,
        LOG
        )

def main() -> None:
    LOG.info("Beginning OSPF Spoofer...")

    # initialise config TODO: UPGRADE TO USE ARGPARSE
    config = OSPFConfig(
            iface="eth0",
            area="0.0.0.0",
            int_ip="192.168.1.100",
            router_id="100.100.100.100",
            authtype=0,
            mask="255.255.255.0",
            )

    session = OSPFSession(config)

    try:
        session.run()
    except KeyboardInterrupt:
        session.running = False
        LOG.info("SPOOFER STOPPED")


if __name__ == "__main__":
    main()
