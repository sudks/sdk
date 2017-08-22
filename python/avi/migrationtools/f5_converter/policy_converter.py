import logging
import avi.migrationtools.f5_converter.converter_constants as final
from avi.migrationtools.f5_converter.conversion_util.py import F5Util

LOG = logging.getLogger(__name__)

# Creating f5 object for util library.
conv_utils = F5Util()

parameters_dict = {'starts-with': 'BEGINS_WITH', 'equals': 'EQUALS',
                   'contains': 'CONTAINS', 'ends-with': 'ENDS_WITH',
                   'not': 'DOES_NOT_'}


class PolicyConfigConv(object):
    def __init__(self):
        pass

    def convert(self, f5_config, avi_config, tenant):
        # Get the policy config from converted parsing
        policy_config = f5_config.get("policy", {})
        print policy_config
        avi_config['HTTPPolicySet'] = []
        for each_policy in policy_config:
            httppolicy = dict()
            httppolicy['name'] = each_policy
            httppolicy['tenant_ref'] = conv_utils.get_object_ref(tenant,
                                                                 'tenant')
            self.create_rules(policy_config[each_policy], httppolicy, tenant,
                              avi_config)
            avi_config['HTTPPolicySet'].append(httppolicy)

    def create_rules(self, config, httppolicy, tenant, avi_config):
        """
        :param config:
        :param httppolicy:
        :return:
        """
        if 'rules' in config:
            for index, each_rule in enumerate(config['rules']):
                if 'conditions' and 'actions' in config['rules'][each_rule]:
                    global_dict = {'name': each_rule, 'enable': True,
                                   'index': index +1}
                    match_rule = config['rules'][each_rule]['conditions']
                    pol_type = self.create_match_rule(match_rule, httppolicy,
                                           global_dict, avi_config, tenant)
                    action_rule = config['rules'][each_rule]['actions']
                    self.create_action_rule(action_rule, httppolicy,
                                            global_dict)
                    httppolicy['http_' + pol_type + '_policy'] = dict()
                    httppolicy['http_' + pol_type + '_policy']['rules'] = []
                    httppolicy['http_' + pol_type + '_policy']['rules'].append(
                                                                    global_dict)

    def create_match_rule(self, match_dict, httppolicy, global_dict,
                          avi_config, tenant):
        """
        :param match_dict:
        :return:
        """
        pol_type = None
        for each_index in match_dict:
            result = match_dict[each_index]
            pol_type = 'response' if 'response' in result else 'request'
            match = None
            path_query = {
                "match_str": [],
                "match_criteria": '',
                'match_case': 'INSENSITIVE'
            }

            path_regex = {
                "match_case": 'INSENSITIVE',
                "string_group_refs": [],
                "match_criteria": ''
            }


            host_header = {
                "match_case": 'INSENSITIVE',
                "value": [],
                "match_criteria": ''
            }

            if 'geoip' in result:
                if 'country-code' in result:
                    client_ip = {
                        'group_refs': [],
                        'match_criteria': 'IS_NOT_IN' if 'not' in result
                                            else 'IS_IN'
                    }
                    match = {'client_ip': client_ip}
                    match['client_ip']['group_refs'].append(
                                             '/api/ipaddrgroup/?name=Internal')
                        #conv_utils.get_object_ref('Internal', 'ipaddrgroup',
                                                  #tenant=tenant))
                    ip_addr_group = {'name': 'Internal',
                                     'tenant_ref': conv_utils.get_object_ref(
                                         tenant, 'tenant'),
                                     'country_code': result['values'].keys()
                                     }
                    if 'IpAddrGroup' not in avi_config:
                        avi_config['IpAddrGroup'] = []
                    avi_config['IpAddrGroup'].append(ip_addr_group)
            elif 'http-cookie' in result:
                cookie = {
                    "match_case": 'INSENSITIVE',
                    "name": result['name'],
                    "value": result['values'].keys()[0],
                    "match_criteria": ''
                }

                match_criteria = [key for key in result if key in
                                  parameters_dict]
                if len(match_criteria) > 1:
                    cookie['match_criteria'] = 'HDR_' + parameters_dict[
                        match_criteria[0]] + (parameters_dict[match_criteria[
                        1]].replace('S',''))
                elif len(match_criteria):
                    if 'not' in match_criteria:
                        cookie['match_criteria'] = 'HDR_' + parameters_dict[
                                                   match_criteria[0]] + 'EQUAL'
                    else:
                        cookie['match_criteria'] = 'HDR_' + parameters_dict[
                                                              match_criteria[0]]
                else:
                    cookie['match_criteria'] = 'HDR_EQUALS'
                match = {'cookie': cookie}
            elif 'http-header' in result:
                header = {
                    "match_case": 'INSENSITIVE',
                    "hdr": result['name'],
                    "value": result['values'].keys(),
                    "match_criteria": ''
                }
                match_criteria = [key for key in result if key in
                                  parameters_dict]
                if len(match_criteria) > 1:
                    header['match_criteria'] = 'HDR_' + parameters_dict[
                        match_criteria[0]] + (parameters_dict[match_criteria[
                        1]].replace('S', ''))
                elif len(match_criteria):
                    if 'not' in match_criteria:
                        header['match_criteria'] = 'HDR_' + parameters_dict[
                            match_criteria[0]] + 'EQUAL'
                    else:
                        header['match_criteria'] = 'HDR_' + parameters_dict[
                            match_criteria[0]]
                else:
                    header['match_criteria'] = 'HDR_EQUALS'
                match = {"hdrs": [header]}







            if 'path' and 'http-uri' in result:
                match_criteria = [key for key in result if key in
                                  parameters_dict.keys()]
                if match_criteria:
                    match_criteria = parameters_dict[str(match_criteria[0])]
                match_policy = \
                    {
                        'match': {
                            'path':{
                                 'match_case': 'INSENSITIVE',
                                 'match_criteria': match_criteria
                            }
                        }
                    }
            if 'values' in match_dict[each_index].keys():
                match_str = match_dict[each_index]['values'].keys()
                match_policy['match']['path']['match_str'] = match_str
            if match:
                global_dict.update({'match': match})
        return pol_type

    def create_action_rule(self, action_dict, httppolicy, global_dict):
        """

        :param action_dict:
        :param httppolicy:
        :return:
        """
        for each_index in action_dict:
            result = action_dict[each_index].keys()
            action_policy = dict()
            if 'redirect' and 'http-reply' and 'location' in result:
                location = action_dict[each_index]['location']
                action_policy = {
                    'redirect_action': {
                       'keep_query': True ,
                        'path':
                            {
                                'tokens':[
                                    {
                                        'str_value': location,
                                        'type': 'URI_TOKEN_TYPE_STRING'
                                    }

                                ],
                                'type': "URI_PARAM_TYPE_TOKENIZED"
                            },
                        'protocol': "HTTP",
                        'port': 80,
                        'status_code': "HTTP_REDIRECT_STATUS_CODE_302"
                    }
                }
                global_dict.update(action_policy)