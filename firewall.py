class Firewall(object):
    """
    Store's a collection of rules read from a file.
    """

    def __init__(self):
        self.rules = []
        pass

    def read_rules_from_file(self, filename):
        with open(filename, 'r') as f:
            for line in f:
                token = line.split()

                permit = token[0]
                pro_type = token[1]

                # Rule with ips
                if len(token) == 6:
                    ip_src = token[3]
                    ip_dst = token[5]
                    self.add_ip_rule_(permit, pro_type, ip_src, ip_dst)
                else:
                    port_loc = token[2]
                    port_num = int(token[3])

                    self.add_port_rule_(permit, pro_type, port_loc, port_num)
                # print(token)

    def add_ip_rule_(self, perm, pro_type, ip_src, ip_dst):
        """
        Add IP rule to firewall list.
        """
        rule = {'perm': perm, 'pro_type': pro_type, 'ip_src': ip_src,
                'port_src': -1, 'ip_dst': ip_dst, 'port_dst': -1}

        self.rules.append(rule)

    def add_port_rule_(self, perm, pro_type, port_loc, port_num):
        """
        Add port rule to firewall list
        """
        rule = None
        if port_loc == 'src':
            rule = {'perm': perm, 'pro_type': pro_type, 'ip_src': '0.0.0.0',
                    'port_src': port_num, 'ip_dst': '0.0.0.0', 'port_dst': -1}
        else:
            rule = {'perm': perm, 'pro_type': pro_type, 'ip_src': '0.0.0.0',
                    'port_src': -1, 'ip_dst': '0.0.0.0', 'port_dst': port_num}
        self.rules.append(rule)
