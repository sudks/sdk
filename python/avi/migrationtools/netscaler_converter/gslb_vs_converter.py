import logging
import avi.migrationtools.netscaler_converter.ns_constants as ns_constants
from avi.migrationtools.netscaler_converter import ns_util
from avi.migrationtools.netscaler_converter.gslb_service_converter \
    import GslbServiceConverter
from avi.migrationtools.netscaler_converter.ns_constants import STATUS_SKIPPED

LOG = logging.getLogger(__name__)


class GslbVsConverter(object):

    def __init__(self):
        self.supported_types = ns_constants.netscalar_command_status[
            'vs_supported_types']
        self.gslb_vserver_indirect = ns_constants.netscalar_command_status[
            'gslb_vserver_indirect']
        self.gslb_vserver_skip = ns_constants.netscalar_command_status[
            'gslb_vserver_skip']
        self.gslb_vserver_na = ns_constants.netscalar_command_status[
            'gslb_vserver_na']

    def convert_lb_method(self, lb_method):
        gslb_algorithm = 'GSLB_ALGORITHM_ROUND_ROBIN'
        if lb_method == 'STATICPROXIMITY':
            gslb_algorithm = 'GSLB_ALGORITHM_GEO'
        elif lb_method == 'SOURCEIPHASH':
            gslb_algorithm = 'GSLB_ALGORITHM_CONSISTENT_HASH'
        return gslb_algorithm

    def convert(self, ns_config, avi_config, vs_state, vip_cluster_map):
        cmd = 'add gslb vserver'
        avi_config['GslbService'] = []
        gslb_vs_conf = ns_config.get(cmd, {})
        gslb_service_converter = GslbServiceConverter()
        for gslb_vs_name in gslb_vs_conf:
            gslb_vs = gslb_vs_conf[gslb_vs_name]
            full_cmd = ns_util.get_netscalar_full_command(cmd, gslb_vs)
            if not gslb_vs['attrs'][1] in self.supported_types:
                skipped_status = 'Skipped:Unsupported type %s of GSLB VS: ' \
                                 '%s' % (type, gslb_vs_name)
                LOG.warning(skipped_status)
                ns_util.add_status_row(gslb_vs['line_no'], cmd, gslb_vs_name,
                                       full_cmd, STATUS_SKIPPED,
                                       skipped_status)
                continue
            lb_method = gslb_vs.get('lbMethod', 'ROUNDROBIN')
            consistent_hash_mask = gslb_vs.get('netmask', None)
            gslb_algorithm = self.convert_lb_method(lb_method)
            groups, ttl, domains = gslb_service_converter.convert(
                ns_config, gslb_vs_name, vip_cluster_map, gslb_algorithm,
                consistent_hash_mask)
            comment = gslb_vs.get('comment', None)

            gslb_service = {
                "name": gslb_vs_name,
                "tenant_ref": "/api/tenant/?name=admin",
                "controller_health_status_enabled": True,
                "wildcard_match": False,
                "enabled": vs_state,
                "ttl": ttl,
                "domain_names": domains,
                "use_edns_client_subnet": True,
                "groups": groups,
                "num_dns_ip": 1,
                "description": comment,
                "health_monitor_scope":
                    "GSLB_SERVICE_HEALTH_MONITOR_ALL_MEMBERS"
            }

            conv_status = ns_util.get_conv_status(
                gslb_vs, self.gslb_vserver_skip, self.gslb_vserver_na,
                self.gslb_vserver_indirect)
            ns_util.add_conv_status(gslb_vs['line_no'], 'add gslb service',
                                    gslb_vs['attrs'][0], full_cmd, conv_status,
                                    gslb_service)

            avi_config['GslbService'].append(gslb_service)