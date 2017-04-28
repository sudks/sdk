import re
import avi.migrationtools.netscaler_converter.ns_constants as ns_constants
from avi.migrationtools.netscaler_converter import ns_util

class GslbServiceConverter(object):
    def __init__(self):
        self.gslb_service_indirect = ns_constants.netscalar_command_status[
            'gslb_service_indirect']
        self.gslb_service_skip = ns_constants.netscalar_command_status[
            'gslb_service_skip']
        self.gslb_service_na = ns_constants.netscalar_command_status[
            'gslb_service_na']
        self.bind_gslb_skip = ns_constants.netscalar_command_status[
            'bind_gslb_skip']

    def convert_service(
            self, ns_service, vip_cluster_map, server_config, ratio):
        cmd = ns_util.get_netscalar_full_command('add gslb service',ns_service)
        matches = re.findall('[0-9]+.[[0-9]+.[0-9]+.[0-9]+',
                             ns_service['attrs'][1])
        if matches:
            member_ip = ns_service['attrs'][1]
        else:
            server = server_config.get(ns_service['attrs'][1], {})
            member_ip = server['attrs'][1]
        state = (ns_service.get('state', 'ENABLED') == 'ENABLED')
        vs_details = vip_cluster_map.get(
            '%s:%s' % (member_ip,  server['attrs'][3]), None)
        if vs_details:
            member = {
                "cluster_uuid": vs_details['cluster_uuid'],
                "ip": {
                    "type": "V4",
                    "addr": member_ip
                },
                "vs_uuid": vs_details['vs_uuid'],
                "ratio": ratio,
                "enabled": state
            }
        else:
            member = {
                "ip": {
                    "type": "V4",
                    "addr": member_ip
                },
                "ratio": ratio,
                "enabled": state
            }

        conv_status = ns_util.get_conv_status(
            ns_service, self.gslb_service_skip, self.gslb_service_na,
            self.gslb_service_indirect)
        ns_util.add_conv_status(ns_service['line_no'], 'add gslb service',
                                ns_service['attrs'][0], cmd, conv_status,
                                member)
        return member

    def convert(self, ns_config, gslb_vs_name, vip_cluster_map, gslb_algorithm,
                consistent_hash_mask):
        print "in service conversion"
        ns_groups = ns_config.get('bind gslb vserver', {})
        gslb_vs_conf = ns_config.get('add gslb vserver', {})
        service_config = ns_config.get('add gslb service', {})
        server_config = ns_config.get('add server')
        vs_bindings = ns_groups.get(gslb_vs_name, {})
        domains=list()
        ttls = list()
        group_dict = dict()
        for binding in vs_bindings:
            cmd = ns_util.get_netscalar_full_command(
                'bind gslb vserver', binding)
            if 'serviceName' in binding:
                member = self.convert_service(
                    service_config[binding['serviceName']], vip_cluster_map,
                    server_config, binding.get('weight', 1))
                priority = binding.get('priority', 1)
                group = group_dict.get(priority, None)
                if not group:
                    group = {
                        'priority': priority,
                        'algorithm': gslb_algorithm,
                        'name': '%s-priority_%s' % (gslb_vs_name, priority),
                        'consistent_hash_mask': consistent_hash_mask,
                        'members': [member]
                    }
                    group_dict[priority] = group
                else:
                    group['members'].append(member)
                conv_status = ns_util.get_conv_status(
                    binding, self.bind_gslb_skip, [], [])
                ns_util.add_conv_status(binding['line_no'], 'add gslb service',
                                        binding['attrs'][0], cmd, conv_status,
                                        group)
            elif 'domainName' in binding:
                domains.append(binding['domainName'])
                ttl = binding.get('TTL', None)
                if ttl:
                    ttls.append(ttl)
                conv_status = ns_util.get_conv_status(
                    binding, self.bind_gslb_skip, [], [])
                ns_util.add_conv_status(binding['line_no'], 'add gslb service',
                                        binding['attrs'][0], cmd, conv_status,
                                        None)
        groups = list()
        for key in group_dict:
            groups.append(group_dict[key])
        ttl = max(ttls, key=ttls.count)

        return groups, ttl, domains
