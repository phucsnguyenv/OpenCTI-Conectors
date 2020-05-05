 while True:
      black_list_file = os.path.dirname(
           os.path.abspath(__file__))+"/ip_blacklist.txt"
       if os.path.isfile(black_list_file):
            print("[31] File IP blacklist existing, deleting file...")
            # deleting file....
            os.remove(black_list_file)
            print("[] File deleted.")
        elif not os.path.isfile(black_list_file):
            print("[33] File not exist or deleted. Downloading new file...")
            ip_blacklist = wget.download(
                self.talosip_url, out="ip_blacklist.txt")
            # processing message...
            ip_lists = open("ip_blacklist.txt", "r")
            print("File downloaded. Processing data...")
            for ip in ip_lists:
                ip = ip.strip("\n")
                indicator = self.helper.api.stix_indicator.create(
                    type="ipv4-addr",
                    observable_value=ip,
                    markingDefinitions='TLP:WHITE',
                    description="from talos via OPENCTI",
                    createIndicator="True"
                )
                print(indicator)
            break
        else:
            raise ValueError(
                "[] Error unknown."
            )
