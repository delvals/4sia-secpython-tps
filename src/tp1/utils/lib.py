from scapy.all import get_if_list


#####################################################################################################
# FUNCS
#####################################################################################################


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    List available network interfaces and prompt the user to pick one.

    :return: selected network interface name
    """
    interfaces = get_if_list()

    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")

    while True:
        try:
            choice = int(input("\nSelect an interface (number): "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            print(f"Please enter a number between 0 and {len(interfaces) - 1}.")
        except ValueError:
            print("Invalid input. Please enter a number.")
