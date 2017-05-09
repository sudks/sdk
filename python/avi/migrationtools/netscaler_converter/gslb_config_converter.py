import logging
import json
from avi.migrationtools.netscaler_converter import ns_util
from avi.sdk.avi_api import ApiSession
from avi.migrationtools.netscaler_converter.gslb_vs_converter \
    import GslbVsConverter

LOG = logging.getLogger(__name__)


def get_vip_cluster_map(sites):
    vip_map=dict()
    for site in sites:
        session = ApiSession.get_session(
            site['ip_addresses'][0]['addr'], site['username'], site['password'])
        resp = session.get('virtualservice', api_version='17.1')
        # resp = session.get('virtualservice', api_version='17.2.1')
        vs_list = json.loads(resp.text)['results']
        for vs in vs_list:
            vip_map.update(create_map_for_vs(vs, vip_map, site))
    return vip_map


def create_map_for_vs(vs, vip_map, site):
    vips = vs['vip']
    services = vs['services']
    for vip in vips:
        for service in services:
            port_range = xrange(int(service['port']),
                                int(service['port_range_end'])+1)
            for port in port_range:
                vip_map['%s:%s' % (vip['ip_address']['addr'], port)] = {
                    'cluster_uuid': site['cluster_uuid'], 'vs_uuid': vs['uuid']}
    return vip_map


def convert(gslb_config_dict, controller_ip, user_name,
            password, tenant_name, vs_state, output_dir, version):

    session = ApiSession.get_session(controller_ip, user_name, password)
    resp = session.get('configuration/export?full_system=true')
    avi_config = json.loads(resp.text)
    # json_data = open('/home/ramesh/Documents/converter/temp.json').read()
    # avi_config = json.loads(json_data)
    sites = avi_config['Gslb'][0]['sites']

    vip_cluster_map = get_vip_cluster_map(sites)
    print vip_cluster_map
    avi_gslb_config = None
    try:
        avi_gslb_config = {
            "META": {
                "supported_migrations": {
                    "versions": [
                        "14_2",
                        "15_1",
                        "15_1_1",
                        "15_2",
                        "15_2_3",
                        "15_3",
                        "16_1",
                        "16_1_1",
                        "16_1_2",
                        "16_1_3",
                        "16_2",
                        "16_2_1",
                        "16_2_2",
                        "16_2_3",
                        "16_3",
                        "16_3_1",
                        "16_3_2",
                        "16_3_4",
                        "16_4_1",
                        "16_4_2",
                        "current_version"
                    ]
                },
                "version": {
                    "Product": "controller",
                    "Version": version,
                    "min_version": 15.2,
                    "ProductName": "Avi Cloud Controller"
                },
                "use_tenant": tenant_name,
                "upgrade_mode": False

            }
        }

        gslb_vs_converter = GslbVsConverter()
        gslb_vs_converter.convert(
            gslb_config_dict, avi_gslb_config, vs_state, vip_cluster_map)

        ns_util.add_complete_conv_status(
            gslb_config_dict, output_dir, avi_config)

    except:
        LOG.error('Error in config conversion', exc_info=True)

    return avi_gslb_config
