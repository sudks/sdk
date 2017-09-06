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

    def convert(self, f5_config, avi_config, tenant, vsname):
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
            if len(httppolicy) > 2:
                avi_config['HTTPPolicySet'].append(httppolicy)
            else:
                LOG.debug('Conversion unsuccessful for the policy %s',
                          each_policy)

    def create_rules(self, config, httppolicy, tenant, avi_config):
        """
        :param config:
        :param httppolicy:
        :return:
        """
        if 'rules' in config:
            for index, each_rule in enumerate(config['rules']):
                if 'conditions' and 'actions' in config['rules'][each_rule]:
                    rule_name = '%s-rule-%s' % (each_rule, str(index + 1))
                    global_dict = {'name': rule_name, 'enable': True,
                                   'index': index + 1}
                    match_rule = config['rules'][each_rule]['conditions']
                    pol_type = self.create_match_rule(match_rule, global_dict,
                                                    avi_config, tenant, index+1)
                    action_rule = config['rules'][each_rule]['actions']
                    self.create_action_rule(action_rule, global_dict,
                                            avi_config)
                    if len(global_dict) >= 5:
                        httppolicy['http_' + pol_type + '_policy'] = dict()
                        httppolicy['http_' + pol_type + '_policy']['rules'] = []
                        httppolicy['http_' + pol_type + '_policy']['rules'
                                                           ].append(global_dict)

    def create_match_rule(self, match_dict, global_dict, avi_config, tenant,
                          index):
        """
        :param match_dict:
        :return:
        """
        pol_type = None
        for each_index in match_dict:
            result = match_dict[each_index]
            pol_type = 'response' if 'response' in result else 'request'
            match = None
            if 'geoip' in result:
                if 'country-code' in result:
                    if 'starts-with' not in result and 'contains' not in \
                            result and 'ends-with' not in result:
                        if 'values' not in result:
                            LOG.debug('Rule is incomplete, values are '
                                      'mandatory')
                            continue
                        client_ip = {
                            'group_refs': [],
                            'match_criteria': 'IS_NOT_IN' if 'not' in result
                                                else 'IS_IN'
                        }
                        ipgrp_name = '%s-%s' % (('local', index) if 'local' in
                                        result else ('Internal', index))
                        match = {'client_ip': client_ip}
                        match['client_ip']['group_refs'].append(
                                       '/api/ipaddrgroup/?name=%s' % ipgrp_name)
                        #conv_utils.get_object_ref('Internal', 'ipaddrgroup',
                                                      #tenant=tenant))
                        ip_addr_group = {'name': ipgrp_name,
                                         'tenant_ref':
                                                      conv_utils.get_object_ref(
                                                              tenant, 'tenant'),
                                         'country_code': result['values'].keys()
                                         }
                        if 'IpAddrGroup' not in avi_config:
                            avi_config['IpAddrGroup'] = []
                        avi_config['IpAddrGroup'].append(ip_addr_group)
                    else:
                        LOG.debug('Condition not supported')
                else:
                    LOG.debug('Selector not supported')
            elif 'http-cookie' in result:
                if 'name' not in result or 'values' not in result:
                    LOG.debug('Rule is incomplete, Name and values are '
                              'mandatory')
                    continue
                cookie = {
                    "match_case": 'INSENSITIVE',
                    "name": result['name'],
                    "value": result['values'].keys()[0],
                    "match_criteria": ''
                }

                match_criteria = [key for key in result if key in
                                  parameters_dict]
                if len(match_criteria) > 1:
                    cookie['match_criteria'] = 'HDR_%s%s' % (parameters_dict[
                        match_criteria[0]], (parameters_dict[match_criteria[
                        1]].replace('S','')))
                elif len(match_criteria):
                    if 'not' in match_criteria:
                        cookie['match_criteria'] = 'HDR_%sEQUAL' % \
                                              parameters_dict[match_criteria[0]]
                    else:
                        cookie['match_criteria'] = 'HDR_%s' % parameters_dict[
                                                              match_criteria[0]]
                else:
                    cookie['match_criteria'] = 'HDR_EQUALS'
                match = {'cookie': cookie}
            elif 'http-header' in result:
                if 'name' not in result or 'values' not in result:
                    LOG.debug('Rule is incomplete, Name and values are '
                              'mandatory')
                    continue
                header = {
                    "match_case": 'INSENSITIVE',
                    "hdr": result['name'],
                    "value": result['values'].keys(),
                    "match_criteria": ''
                }
                match_criteria = [key for key in result if key in
                                  parameters_dict]
                if len(match_criteria) > 1:
                    header['match_criteria'] = 'HDR_%s%s' % (parameters_dict[
                        match_criteria[0]], (parameters_dict[match_criteria[
                        1]].replace('S', '')))
                elif len(match_criteria):
                    if 'not' in match_criteria:
                        header['match_criteria'] = 'HDR_%sEQUAL' % \
                                              parameters_dict[match_criteria[0]]
                    else:
                        header['match_criteria'] = 'HDR_%s' % parameters_dict[
                                                              match_criteria[0]]
                else:
                    header['match_criteria'] = 'HDR_EQUALS'
                match = {"hdrs": [header]}
            elif 'http-host' in result:
                if 'host' not in result and 'port' not in result:
                    if 'values' not in result:
                        LOG.debug('Rule is incomplete, Values are mandatory')
                        continue
                    host_header = {
                        "match_case": 'INSENSITIVE',
                        "value": result['values'].keys(),
                        "match_criteria": ''
                    }
                    match_criteria = [key for key in result if key in
                                      parameters_dict]
                    if len(match_criteria) > 1:
                        header['match_criteria'] = 'HDR_%s%s' % (parameters_dict
                            [match_criteria[0]], (parameters_dict[match_criteria
                            [1]].replace('S', '')))
                    elif len(match_criteria):
                        if 'not' in match_criteria:
                            header['match_criteria'] = 'HDR_%sEQUAL' % \
                                              parameters_dict[match_criteria[0]]
                        else:
                            header['match_criteria'] = 'HDR_%s' % \
                                              parameters_dict[match_criteria[0]]
                    else:
                        header['match_criteria'] = 'HDR_EQUALS'
                    match = {"host_hdr": host_header}
                else:
                    LOG.debug('Selector not supported')
            elif 'http-method' in result:
                if 'starts-with' not in result and 'contains' not in \
                            result and 'ends-with' not in result:
                    if 'values' not in result:
                        LOG.debug('Rule is incomplete, Values are mandatory')
                        continue
                    avi_method = ['OPTIONS', 'PUT', 'HEAD', 'DELETE', 'GET',
                                  'POST', 'TRACE', 'options', 'put', 'head',
                                  'get', 'delete', 'post', 'trace']
                    invalid = [True if val not in avi_method else False for
                               val in result['values'].keys()]
                    if all(invalid):
                        LOG.debug('All methods %s are invalid', str(result[
                                                            'values'].keys()))
                        continue
                    method = {
                        'methods': ['HTTP_METHOD_%s' % val.upper() for val in
                                    result['values'].keys()],
                        'match_criteria': 'IS_NOT_IN' if 'not' in result
                                            else 'IS_IN'
                    }
                    match = {'method': method}
                else:
                    LOG.debug('Condition not supported')
            elif 'http-uri' in result:
                if 'path' in result:
                    if 'values' not in result:
                        LOG.debug('Rule is incomplete, Values are mandatory')
                        continue
                    path_query = {
                        "match_str": result['values'].keys(),
                        "match_criteria": '',
                        'match_case': 'INSENSITIVE'
                    }
                    match_criteria = [key for key in result if key in
                                        parameters_dict.keys()]
                    if len(match_criteria) > 1:
                        header['match_criteria'] = 'HDR_%s%s' % (parameters_dict
                            [match_criteria[0]], (parameters_dict[match_criteria
                            [1]].replace('S', '')))
                    elif len(match_criteria):
                        if 'not' in match_criteria:
                            header['match_criteria'] = 'HDR_%sEQUAL' % \
                                              parameters_dict[match_criteria[0]]
                        else:
                            header['match_criteria'] = 'HDR_%s' % \
                                              parameters_dict[match_criteria[0]]
                    else:
                        header['match_criteria'] = 'HDR_EQUALS'
                    match = {"path": path_query}
                else:
                    LOG.debug('Selector not supported')
            elif 'http-version' in result:
                if 'major' not in result and 'minor' not in result and \
                        'protocol' not in result:
                    if 'starts-with' not in result and 'contains' not in \
                                result and 'ends-with' not in result:
                        if 'values' not in result:
                            LOG.debug('Rule is incomplete, Values are '
                                      'mandatory')
                            continue
                        avi_version = ['ZERO_NINE', 'ONE_ZERO', 'ONE_ONE',
                                       'zero_nine', 'one_zero', 'one_one']
                        invalid = [True if val not in avi_version else False for
                                   val in result['values'].keys()]
                        if all(invalid):
                            LOG.debug('All versions %s are invalid', str(result[
                                                              'values'].keys()))
                            continue
                        version = {
                            'versions': [val.upper() for val in result[
                                            'values'].keys()],
                            'match_criteria': 'IS_NOT_IN' if 'not' in result
                                                else 'IS_IN'
                        }
                        match = {'version': version}
                    else:
                        LOG.debug('Condition not supported')
                else:
                    LOG.debug('Selector not supported')
            elif 'http-status' in result:
                if 'code' in result:
                    if 'less' not in result and 'greater' not in result and \
                      'less-or-equal' not in result and 'greater-or-equal' \
                      not in result:
                        if 'values' not in result:
                            LOG.debug('Rule is incomplete, Values are '
                                      'mandatory')
                            continue
                        status = {
                            'status_codes': result['values'].keys(),
                            'match_criteria': 'IS_NOT_IN' if 'not' in result
                                                else 'IS_IN'
                        }
                        match = {'status': status}
                    else:
                        LOG.debug('Condition not supported')
                else:
                    LOG.debug('Selector not supported')
            else:
                LOG.debug('Rule match not supported')
                return
            if match:
                global_dict.update({'match': match})
        return pol_type

    def create_action_rule(self, action_dict, httppolicy, global_dict,
                           avi_config):
        """

        :param action_dict:
        :param httppolicy:
        :return:
        """
        for each_index in action_dict:
            result = action_dict[each_index]
            pol_type = 'response' if 'response' in result else 'request'
            action = None
            if 'forward' in result:
                if 'select' in result:
                    if 'pool' in result:
                        action = {
                            'switching_action': {
                                'status_code':
                                    'HTTP_LOCAL_RESPONSE_STATUS_CODE_200',
                            }
                        }
                        poolname = conv_utils.get_tenant_ref(result['pool'])
                        poolobj = [obj for obj in avi_config['Pool'] if
                                   poolname == obj['name']]
                        if poolobj:
                            action['action'] = 'HTTP_SWITCHING_SELECT_POOL'
                            action['pool_ref'] = conv_utils.get_object_ref(
                                                    poolobj[0]['name'], 'pool')
                        else:
                            pgobj = [ob for ob in avi_config['PoolGroup'] if
                                     poolname == ob['name']]
                            action['action'] = 'HTTP_SWITCHING_SELECT_POOLGROUP'
                            action['pool_group_ref'] = \
                                conv_utils.get_object_ref(pgobj[0]['name'],
                                                          'poolgroup')
                    else:
                        LOG.debug('Parameter not supported')
                else:
                    LOG.debug('Action not supported')
            elif 'http' in result:
                if pol_type == 'request':
                    action = {
                        'redirect_action': {
                            'keep_query': True,
                            'status_code': 'HTTP_REDIRECT_STATUS_CODE_302',
                            'protocol': 'HTTP',
                            'port': 80
                        }
                    }
                else:
                    LOG.debug('Event not supported')
            elif 'http-header' in result:
                action = {
                    'hdr_action': [
                        {
                            'action': '',
                            'hdr': {
                                        'name': result['name']
                            }
                        }
                    ]
                }
                if 'remove' in result:
                    action['hdr_action'][0]['action'] = 'HTTP_REMOVE_HDR'
                elif 'replace' in result:
                    action['hdr_action'][0]['action'] = 'HTTP_REPLACE_HDR'
                    action['hdr_action'][0]['hdr']['value'] = {}
                    action['hdr_action'][0]['hdr']['value']['val'] = result[
                                                                        'value']
                elif 'insert' in result:
                    action['hdr_action'][0]['action'] = 'HTTP_ADD_HDR'
                    action['hdr_action'][0]['hdr']['value'] = {}
                    action['hdr_action'][0]['hdr']['value']['val'] = result[
                                                                        'value']
            elif 'http-host' in result and 'replace' in result:
                action = {
                    'hdr_action': [
                        {
                            'action': 'HTTP_REPLACE_HDR',
                            'hdr': {
                                'name': result['name'],
                                'value': {
                                    'val': result['value']
                                }
                            }
                        }
                    ]
                }
            elif 'http-reply' in result and 'redirect' in result and \
              'location' in result:
                if pol_type == 'request':
                    action = {
                        'redirect_action': {
                           'keep_query': True,
                           'path':
                                {
                                    'tokens': [
                                        {
                                            'str_value': result['location'],
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
                else:
                    LOG.debug('Event not supported')
            else:
                LOG.debug('Rule action not supported')
                return
            if action:
                global_dict.update(action)