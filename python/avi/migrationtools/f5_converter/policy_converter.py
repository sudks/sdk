import logging
import avi.migrationtools.f5_converter.converter_constants as final
from avi.migrationtools.f5_converter.conversion_util import F5Util

LOG = logging.getLogger(__name__)

# Creating f5 object for util library.
conv_utils = F5Util()

parameters_dict = {'starts-with': 'BEGINS_WITH', 'equals': 'EQUALS',
                   'contains': 'CONTAINS', 'ends-with': 'ENDS_WITH',
                   'not': 'DOES_NOT_'}
used_pools = {}


class PolicyConfigConv(object):
    @classmethod
    def get_instance(cls, version, f5_policy_attributes, prefix):
        if version == '10':
            return PolicyConfigConvV10(f5_policy_attributes, prefix)
        if version in ['11', '12']:
            return PolicyConfigConvV11(f5_policy_attributes, prefix)

    def convert(self, f5_config, avi_config, tenant):
        # Get the policy config from converted parsing
        policy_config = f5_config.get("policy", {})
        for each_policy in policy_config:
            LOG.debug("Conversion started for the policy %s", each_policy)
            policy_name = conv_utils.get_tenant_ref(each_policy)[1]
            if self.prefix:
                policy_name = '%s-%s' % (self.prefix, policy_name)
            httppolicy = dict()
            config = policy_config[each_policy]
            self.create_rules(config, httppolicy, tenant, avi_config,
                              policy_name)
            if httppolicy.get('http_request_policy', httppolicy.get(
                    'http_response_policy')):
                httppolicy['name'] = policy_name
                httppolicy['tenant_ref'] = conv_utils.get_object_ref(tenant,
                                                                     'tenant')
                httppolicy["is_internal_policy"] = False
                avi_config['HTTPPolicySet'].append(httppolicy)
                conv_status = {'status': final.STATUS_SUCCESSFUL}
                conv_utils.add_conv_status('policy', None, each_policy,
                                           conv_status, httppolicy)
            else:
                conv_utils.add_status_row("policy", None, each_policy,
                                          final.STATUS_SKIPPED)
                LOG.debug('Skipping:Conversion unsuccessful for the policy %s',
                          each_policy)

    def create_rules(self, config, httppolicy, tenant, avi_config,
                     policy_name):
        """
        :param config:
        :param httppolicy:
        :return:
        """
        if 'rules' in config:
            for index, each_rule in enumerate(config['rules']):
                if config['rules'][each_rule].get('conditions') and config[
                  'rules'][each_rule].get('actions'):
                    rule_name = '%s-%s-%s' % (policy_name, each_rule,
                                              str(index + 1))
                    rule_dict = {'name': rule_name, 'enable': True,
                                   'index': index + 1}
                    match_rule = config['rules'][each_rule]['conditions']
                    pol_type, match, skip_match = self.create_match_rule(
                        match_rule, avi_config, tenant, rule_name, each_rule)
                    if not match:
                        LOG.debug('All match conditions not supported for rule '
                                  '%s in policy %s', each_rule, policy_name)
                        continue
                    else:
                        LOG.debug('Rule match successfully converted for rule '
                                  '%s in policy %s', each_rule, policy_name)
                    action_rule = config['rules'][each_rule]['actions']
                    actions, skip_action = self.create_action_rule(action_rule,
                                            avi_config, each_rule, policy_name)
                    if not actions:
                        LOG.debug('All actions not supported for rule %s '
                                  'in policy %s', each_rule, policy_name)
                        continue
                    else:
                        LOG.debug('Rule action successfully converted for rule '
                                  '%s in policy %s', each_rule, policy_name)
                    rule_dict.update({'match': match})
                    for act in actions:
                        rule_dict.update(act)
                    if pol_type:
                        if not httppolicy.get('http_' + pol_type + '_policy'):
                            httppolicy['http_' + pol_type + '_policy'] = dict()
                            httppolicy['http_' + pol_type + '_policy'][
                                'rules'] = []
                        httppolicy['http_' + pol_type + '_policy'][
                            'rules'].append(rule_dict)
                elif config['rules'][each_rule].get('conditions'):
                    LOG.debug('Skipping rule:No action found for rule %s in '
                              'policy %s', each_rule, policy_name)
                elif config['rules'][each_rule].get('actions'):
                    LOG.debug('Skipping rule:No match condition found for rule '
                              '%s in policy %s', each_rule, policy_name)
                else:
                    LOG.debug('Skipping rule:Match conditions and actions are '
                              'missing for policy %s', policy_name)
        else:
            LOG.debug('No rule found for policy %s', policy_name)

    def create_match_rule(self, match_dict, avi_config, tenant,
                          rule_name, each_rule):
        """
        :param match_dict:
        :return:
        """
        pol_type = None
        match = {}
        skip_match = dict()
        skip_match[each_rule] = []
        LOG.debug('Started making match for rule %s', each_rule)
        for each_index in match_dict:
            result = match_dict[each_index]
            op = None
            skip_parameter, skip_selector, skip_op, skip_event = [], [], [], []
            if 'geoip' in result:
                op = 'geoip'
                if 'response' in result:
                    pol_type = 'response'
                elif 'ssl-client-hello' in result:
                    skip_event.append('ssl-client-hello')
                    LOG.debug("Event 'ssl-client-hello' not supported for "
                              "operand %s", op)
                    continue
                elif 'ssl-server-handshake' in result:
                    skip_event.append('ssl-server-handshake')
                    LOG.debug("Event 'ssl-server-handshake' not supported for "
                              "operand %s", op)
                    continue
                elif 'ssl-sever-hello' in result:
                    skip_event.append('ssl-sever-hello')
                    LOG.debug("Event 'ssl-sever-hello' not supported for "
                              "operand %s", op)
                    continue
                else:
                    pol_type = 'request'
                if 'country-code' in result:
                    if 'starts-with' not in result and 'contains' not in \
                            result and 'ends-with' not in result:
                        if 'values' not in result:
                            LOG.debug('Match rule is incomplete, values are '
                                      'mandatory for operand %s', op)
                            continue
                        client_ip = {
                            'group_refs': [],
                            'match_criteria': 'IS_NOT_IN' if 'not' in result
                                                else 'IS_IN'
                        }
                        if 'Internal' in result:
                            client_ip['group_refs'].append(
                                              '/api/ipaddrgroup/?name=Internal')
                        if 'local' in result:
                            skip_parameter.append('local')
                        ipgrp_name = '%s-%s' % (rule_name, str(each_index))
                        ip_addr_group = {'name': ipgrp_name,
                                         'tenant_ref':
                                                      conv_utils.get_object_ref(
                                                              tenant, 'tenant'),
                                         'country_code': result['values'].keys()
                                         }
                        if 'IpAddrGroup' not in avi_config:
                            avi_config['IpAddrGroup'] = []
                        avi_config['IpAddrGroup'].append(ip_addr_group)
                        client_ip['group_refs'].append(
                                       '/api/ipaddrgroup/?name=%s' % ipgrp_name)
                        match['client_ip'] = client_ip
                    else:
                        if 'starts-with' in result:
                            skip_op.append('starts-with')
                        elif 'contains' in result:
                            skip_op.append('contains')
                        elif 'ends-with' in result:
                            skip_op.append('ends-with')
                        if 'case-sensitive' in result:
                            skip_op.append('case-sensitive')
                        if 'missing' in result:
                            skip_op.append('missing')
                        if skip_op:
                            LOG.debug("Condition '%s' not supported for operand"
                                      " %s", str(skip_op), op)
                else:
                    if 'continent' in result:
                        skip_selector.append('continent')
                    elif 'country-name' in result:
                        skip_selector.append('country-name')
                    elif 'isp' in result:
                        skip_selector.append('isp')
                    elif 'organization' in result:
                        skip_selector.append('organization')
                    elif 'region-code' in result:
                        skip_selector.append('region-code')
                    elif 'region-name' in result:
                        skip_selector.append('region-name')
                    if skip_selector:
                        LOG.debug("Selector '%s' not supported for operand %s",
                                  str(skip_selector), op)
            elif 'http-cookie' in result:
                op = 'http-cookie'
                pol_type = 'response' if 'response' in result else 'request'
                if not pol_type:
                    LOG.debug('Event not supported for operand %s', op)
                    continue
                if 'name' not in result or 'values' not in result:
                    LOG.debug('Match rule is incomplete, Name and values are '
                              'mandatory for operand %s', op)
                    continue
                if 'missing' in result:
                    skip_op.append('missing')
                    LOG.debug("Condition 'missing' not supported for operand %s"
                              , op)
                if len(result['values']) > 1:
                    LOG.debug('More than one value can not be used for op %s, '
                              'using the any one', op)
                cookie = {
                    "match_case": 'SENSITIVE' if 'case-sensitive' in result
                                    else 'INSENSITIVE',
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
                match['cookie'] = cookie
            elif 'http-header' in result:
                op = 'http-header'
                pol_type = 'response' if 'response' in result else 'request'
                if not pol_type:
                    LOG.debug('Event not supported for operand %s', op)
                    continue
                if 'name' not in result or 'values' not in result:
                    LOG.debug('Match rule is incomplete, Name and values are '
                              'mandatory for operand %s', op)
                    continue
                if 'missing' in result:
                    skip_op.append('missing')
                    LOG.debug("Condition 'missing' not supported for operand %s"
                              , op)
                header = {
                    "match_case": 'SENSITIVE' if 'case-sensitive' in result
                                    else 'INSENSITIVE',
                    "hdr": result['name'],
                    "value": result['values'].keys(),
                    "match_criteria": ''
                }
                match_criteria = [key for key in result if key in
                                  parameters_dict]
                if len(match_criteria) > 1:
                    header['match_criteria'] = 'HDR_%s%s' % (parameters_dict[
                        match_criteria[0]], (parameters_dict[
                        match_criteria[1]].replace('S', '')))
                elif len(match_criteria):
                    if 'not' in match_criteria:
                        header['match_criteria'] = 'HDR_%sEQUAL' % \
                                              parameters_dict[match_criteria[0]]
                    else:
                        header['match_criteria'] = 'HDR_%s' % parameters_dict[
                                                              match_criteria[0]]
                else:
                    header['match_criteria'] = 'HDR_EQUALS'
                if 'hdrs' not in match:
                    match['hdrs']=[]
                match['hdrs'].append(header)
            elif 'http-host' in result:
                op = 'http-host'
                if 'values' not in result:
                    LOG.debug('Match rule is incomplete, Values are '
                              'mandatory for op %s', op)
                    continue
                pol_type = 'response' if 'response' in result else 'request'
                if not pol_type:
                    LOG.debug('Event not supported for operand %s', op)
                    continue
                if 'missing' in result:
                    skip_op.append('missing')
                    LOG.debug("Condition 'missing' not supported for "
                              "operand %s", op)
                if 'port' not in result:
                    host_header = {
                        "match_case": 'SENSITIVE' if 'case-sensitive' in result
                                        else 'INSENSITIVE',
                        "value": result['values'].keys(),
                        "match_criteria": ''
                    }
                    match_criteria = [key for key in result if key in
                                      parameters_dict]
                    if len(match_criteria) > 1:
                        host_header['match_criteria'] = 'HDR_%s%s' % (
                           parameters_dict[match_criteria[0]], (
                           parameters_dict[match_criteria[1]].replace('S', '')))
                    elif len(match_criteria):
                        if 'not' in match_criteria:
                            host_header['match_criteria'] = 'HDR_%sEQUAL' % \
                                              parameters_dict[match_criteria[0]]
                        else:
                            host_header['match_criteria'] = 'HDR_%s' % \
                                              parameters_dict[match_criteria[0]]
                    else:
                        host_header['match_criteria'] = 'HDR_EQUALS'
                    match["host_hdr"] = host_header
                else:
                    if 'less' not in result and 'greater' not in result and \
                      'less-or-equal' not in result and 'greater-or-equal' \
                      not in result:
                        service_port = {
                            'ports': result['values'].keys(),
                            'match_criteria': 'IS_NOT_IN' if 'not' in result
                                                else 'IS_IN'
                        }
                        match["vs_port"] = service_port
                    else:
                        if 'less' in result:
                            skip_op.append('less')
                        elif 'greater' in result:
                            skip_op.append('greater')
                        elif 'less-or-equal' in result:
                            skip_op.append('less-or-equal')
                        elif 'greater-or-equal' in result:
                            skip_op.append('greater-or-equal')
                        if 'case-sensitive' in result:
                            skip_op.append('case-sensitive')
                        if skip_op:
                            LOG.debug("Condition '%s' not supported for "
                                      "parameter 'port' in operand"
                                      " %s", str(skip_op), op)
            elif 'http-method' in result:
                op = 'http-method'
                if 'values' not in result:
                    LOG.debug('Match rule is incomplete, Values are '
                              'mandatory for op %s', op)
                    continue
                pol_type = 'response' if 'response' in result else 'request'
                if not pol_type:
                    LOG.debug('Event not supported for operand %s', op)
                    continue
                if 'starts-with' not in result and 'contains' not in \
                            result and 'ends-with' not in result:
                    avi_method = ['OPTIONS', 'PUT', 'HEAD', 'DELETE', 'GET',
                                  'POST', 'TRACE', 'options', 'put', 'head',
                                  'get', 'delete', 'post', 'trace']
                    invalid = [True if val not in avi_method else False for
                               val in result['values'].keys()]
                    if all(invalid):
                        LOG.debug('All methods %s are invalid', str(result[
                                                            'values'].keys()))
                        continue
                    else:
                        valid = [val for val in result['values'].keys() if
                                 val in avi_method]
                        LOG.debug('Only these %s methods are valid', str(valid))
                    method = {
                        'methods': ['HTTP_METHOD_%s' % val.upper() for val in
                                    valid],
                        'match_criteria': 'IS_NOT_IN' if 'not' in result
                                            else 'IS_IN'
                    }
                    match['method'] = method
                else:
                    if 'starts-with' in result:
                        skip_op.append('starts-with')
                    elif 'contains' in result:
                        skip_op.append('contains')
                    elif 'ends-with' in result:
                        skip_op.append('ends-with')
                    if 'case-sensitive' in result:
                        skip_op.append('case-sensitive')
                    if 'missing' in result:
                        skip_op.append('missing')
                    if skip_op:
                        LOG.debug("Condition '%s' not supported for operand"
                                  " %s", str(skip_op), op)
            elif 'http-referer' in result:
                op = 'http-referer'
                pol_type = 'response' if 'response' in result else 'request'
                if not pol_type:
                    LOG.debug('Event not supported for operand %s', op)
                    continue
                if 'values' not in result:
                    LOG.debug('Match rule is incomplete, values are '
                              'mandatory for operand %s', op)
                    continue
                if 'missing' in result:
                    skip_op.append('missing')
                    LOG.debug("Condition 'missing' not supported for operand %s"
                              , op)
                header = {
                    "match_case": 'SENSITIVE' if 'case-sensitive' in result
                                    else 'INSENSITIVE',
                    "hdr": 'referer',
                    "value": result['values'].keys(),
                    "match_criteria": ''
                }
                match_criteria = [key for key in result if key in
                                  parameters_dict]
                if len(match_criteria) > 1:
                    header['match_criteria'] = 'HDR_%s%s' % (parameters_dict[
                        match_criteria[0]], (parameters_dict[
                        match_criteria[1]].replace('S', '')))
                elif len(match_criteria):
                    if 'not' in match_criteria:
                        header['match_criteria'] = 'HDR_%sEQUAL' % \
                                              parameters_dict[match_criteria[0]]
                    else:
                        header['match_criteria'] = 'HDR_%s' % parameters_dict[
                                                              match_criteria[0]]
                else:
                    header['match_criteria'] = 'HDR_EQUALS'
                if 'hdrs' not in match:
                    match['hdrs']=[]
                match['hdrs'].append(header)
            elif 'http-uri' in result:
                op = 'http-uri'
                pol_type = 'response' if 'response' in result else 'request'
                if not pol_type:
                    LOG.debug('Event not supported for operand %s', op)
                    continue
                if 'path' in result:
                    if 'values' not in result:
                        LOG.debug('Match rule is incomplete, Values are '
                                  'mandatory for operand %s', op)
                        continue
                    path_query = {
                        "match_str": result['values'].keys(),
                        "match_criteria": '',
                        'match_case': 'INSENSITIVE'
                    }
                    match_criteria = [key for key in result if key in
                                        parameters_dict.keys()]
                    if len(match_criteria) > 1:
                        path_query['match_criteria'] = '%s%s' % (
                           parameters_dict[match_criteria[0]], (
                           parameters_dict[match_criteria[1]].replace('S', '')))
                    elif len(match_criteria):
                        if 'not' in match_criteria:
                            path_query['match_criteria'] = '%sEQUAL' % \
                                              parameters_dict[match_criteria[0]]
                        else:
                            path_query['match_criteria'] = '%s' % \
                                              parameters_dict[match_criteria[0]]
                    else:
                        path_query['match_criteria'] = 'EQUALS'
                    match["path"] = path_query
                else:
                    if 'extension' in result:
                        skip_selector.append('extension')
                    elif 'host'  in result:
                        skip_selector.append('host')
                    elif 'path-segment' in result:
                        skip_selector.append('path-segment')
                    elif 'port' in result:
                        skip_selector.append('port')
                    elif 'query-parameters' in result:
                        skip_selector.append('query-parameters')
                    elif 'query-string' in result:
                        skip_selector.append('query-string')
                    elif 'scheme' in result:
                        skip_selector.append('scheme')
                    elif 'unamed-query-parameter' in result:
                        skip_selector.append('unamed-query-parameter')
                    else:
                        skip_selector.append('all')
                    if skip_selector:
                        LOG.debug(
                            "Selector '%s' not supported for operand %s",
                            str(skip_selector), op)
            elif 'http-version' in result:
                op = 'http-version'
                pol_type = 'response' if 'response' in result else 'request'
                if not pol_type:
                    LOG.debug('Event not supported for operand %s', op)
                    continue
                if 'values' not in result:
                    LOG.debug('Match rule is incomplete, values are '
                              'mandatory for operand %s', op)
                    continue
                if 'starts-with' not in result and 'contains' not in \
                        result and 'ends-with' not in result:
                    if 'major' not in result and 'minor' not in result and \
                            'protocol' not in result:
                        avi_version = ['ZERO_NINE', 'ONE_ZERO', 'ONE_ONE',
                                       'zero_nine', 'one_zero', 'one_one']
                        invalid = [True if val not in avi_version else False for
                                   val in result['values'].keys()]
                        if all(invalid):
                            LOG.debug('All versions %s are invalid', str(result[
                                                              'values'].keys()))
                            continue
                        else:
                            valid = [val for val in result['values'].keys()
                                     if val in avi_version]
                            LOG.debug('Only these %s versions are valid',
                                      str(valid))
                        version = {
                            'versions': [val.upper() for val in valid],
                            'match_criteria': 'IS_NOT_IN' if 'not' in result
                                                else 'IS_IN'
                        }
                        match['version'] = version
                    elif 'protocol' in result:
                        if 'not' not in result:
                            avi_protocol = ['HTTP', 'HTTPS']
                            invalid = [True if val not in avi_protocol else
                                       False for val in result['values'].keys()]
                            if all(invalid):
                                LOG.debug('All protocols %s are invalid',
                                          str(result['values'].keys()))
                                continue
                            else:
                                valid = [val for val in result['values'].keys()
                                         if val in avi_protocol]
                                LOG.debug('Only these protocols %s are valid',
                                          str(avi_protocol))
                            if len(valid) > 1:
                                LOG.debug("Only one value is supported at a "
                                          "time for 'protocol' in operand %s, "
                                          "taking any one", op)
                            protocol = {
                                'protocols': valid[0],
                                'match_criteria': 'IS_IN'
                            }
                            match['protocol'] = protocol
                        else:
                            skip_op.append('not')
                            LOG.debug("Condition 'not' not supported for "
                                      "'protocol' in operand %s", op)
                    else:
                        if 'major' in result:
                            skip_selector.append('major')
                        elif 'minor' in result:
                            skip_selector.append('minor')
                        if skip_selector:
                            LOG.debug(
                                "Selector '%s' not supported for operand %s",
                                str(skip_selector), op)
                else:
                    if 'starts-with' in result:
                        skip_op.append('starts-with')
                    elif 'contains' in result:
                        skip_op.append('contains')
                    elif 'ends-with' in result:
                        skip_op.append('ends-with')
                    if 'case-sensitive' in result:
                        skip_op.append('case-sensitive')
                    if 'missing' in result:
                        skip_op.append('missing')
                    if skip_op:
                        LOG.debug("Condition '%s' not supported for operand"
                                  " %s", str(skip_op), op)
            elif 'http-status' in result:
                op = 'http-status'
                pol_type = 'response' if 'response' in result else None
                if not pol_type:
                    LOG.debug('Event not supported for operand %s', op)
                    continue
                if 'code' in result:
                    if 'less' not in result and 'greater' not in result and \
                      'less-or-equal' not in result and 'greater-or-equal' \
                      not in result:
                        if 'values' not in result:
                            LOG.debug('Match rule is incomplete, Values are '
                                      'mandatory for operand %s', op)
                            continue
                        status = {
                            'match_criteria': 'IS_NOT_IN' if 'not' in result
                                                else 'IS_IN'
                        }
                        status_code = [val for val in result[
                                            'values'].keys() if '-' not in val]
                        if status_code:
                            status['status_codes'] = status_code
                        ranges = [{'begin': stat_code.split('-')[0], 'end':
                                  stat_code.split('-')[1]} for stat_code in
                                  result['values'].keys() if '-' in stat_code]
                        if ranges:
                            status['ranges'] = ranges
                        match['status'] = status
                    else:
                        if 'less' in result:
                            skip_op.append('less')
                        elif 'greater' in result:
                            skip_op.append('greater')
                        elif 'less-or-equal' in result:
                            skip_op.append('less-or-equal')
                        elif 'greater-or-equal' in result:
                            skip_op.append('greater-or-equal')
                        if 'case-sensitive' in result:
                            skip_op.append('case-sensitive')
                        if 'missing' in result:
                            skip_op.append('missing')
                        if skip_op:
                            LOG.debug("Condition '%s' not supported for "
                                      "operand %s", str(skip_op), op)
                else:
                    if 'text' in result:
                        skip_selector.append('text')
                    else:
                        skip_selector.append('all')
                    if skip_selector:
                        LOG.debug("Selector %s not supported for operand %s",
                                  str(skip_selector), op)
            else:
                LOG.debug('Rule match %s not supported for rule %s',
                          str(result), each_rule)
            if op:
                skip_match[each_rule].append(
                    {op: {'selector': skip_selector,
                          'parameter': skip_parameter,
                          'condn_op': skip_op,
                          'event': skip_event
                          }
                    })
        return pol_type, match, skip_match

    def create_action_rule(self, action_dict, avi_config, each_rule,
                           policy_name):
        """

        :param action_dict:
        :param avi_config:
        :param each_rule:
        :return:
        """
        action_list = []
        skip_actions = dict()
        skip_actions[each_rule] = []
        LOG.debug('Started making action for rule %s', each_rule)
        for each_index in action_dict:
            if [act for act in action_list if act.get('redirect_action')]:
                LOG.debug("Rule '%s' has 'redirect_action' hence, can't have "
                          "any other action", each_rule)
                return
            action = None
            target = None
            skip_event, skip_target = [], []
            skip_action, skip_parameter = [], []
            result = action_dict[each_index]
            pol_type = 'response' if 'response' in result else 'request'
            if 'forward' in result:
                target = 'forward'
                if 'select' in result:
                    if 'pool' in result:
                        action = {
                            'switching_action': {
                                'status_code':
                                    'HTTP_LOCAL_RESPONSE_STATUS_CODE_200'
                            }
                        }
                        poolname = conv_utils.get_tenant_ref(result['pool'])[1]
                        if self.prefix:
                            poolname = '%s-%s' % (self.prefix, poolname)
                        poolobj = [obj for obj in avi_config['Pool'] if
                                   poolname == obj['name']]
                        if poolobj:
                            action['switching_action']['action'] = \
                                'HTTP_SWITCHING_SELECT_POOL'
                            action['switching_action']['pool_ref'] = \
                                conv_utils.get_object_ref(
                                poolobj[0]['name'], 'pool')
                            if poolname not in used_pools:
                                used_pools[poolname] = set(policy_name)
                            else:
                                used_pools[poolname].add(policy_name)
                        else:
                            pgobj = [ob for ob in avi_config.get['PoolGroup']
                                     if poolname == ob['name']]
                            if pgobj:
                                action['switching_action']['action'] = \
                                    'HTTP_SWITCHING_SELECT_POOLGROUP'
                                action['switching_action']['pool_group_ref'] = \
                                    conv_utils.get_object_ref(pgobj[0]['name'],
                                                              'poolgroup')
                                if poolname not in used_pools:
                                    used_pools[poolname] = set(policy_name)
                                else:
                                    used_pools[poolname].add(policy_name)
                            else:
                                LOG.debug("No pool/poolgroup '%s' found",
                                          poolname)
                                continue
                    else:
                        if 'clone-pool' in result:
                            skip_parameter.append('clone-pool')
                        elif 'member' in result:
                            skip_parameter.append('member')
                        elif 'nexthop' in result:
                            skip_parameter.append('nexthop')
                        elif 'node' in result:
                            skip_parameter.append('node')
                        elif 'rateclass' in result:
                            skip_parameter.append('rateclass')
                        elif 'snat' in result:
                            skip_parameter.append('snat')
                        elif 'snatpool'  in result:
                            skip_parameter.append('snatpool')
                        elif 'virtualserver'  in result:
                            skip_parameter.append('virtualserver')
                        elif 'vlan'  in result:
                            skip_parameter.append('vlan')
                        elif 'vlan_id'  in result:
                            skip_parameter.append('vlan_id')
                        if skip_parameter:
                            LOG.debug('Parameter %s not supported for target '
                                      '%s', str(skip_parameter), target)
                else:
                    if 'reset' in result:
                        skip_action.append('reset')
                        LOG.debug("Action 'reset' not supported for target %s",
                                  target)
            elif 'http' in result:
                target = 'http'
                if pol_type == 'request':
                    if 'enable' in result:
                        action = {
                            'redirect_action': {
                                'keep_query': True,
                                'status_code': 'HTTP_REDIRECT_STATUS_CODE_302',
                                'protocol': 'HTTP',
                                'port': 80
                            }
                        }
                    else:
                        skip_action.append('disable')
                        LOG.debug("Action 'disable' not supported for target "
                                  "%s", target)
                else:
                    skip_event.append('response')
                    LOG.debug("Event 'response' not supported for target %s",
                              target)
            elif 'http-header' in result:
                target = 'http-header'
                if 'name' not in result:
                    LOG.debug("Mandatory parameter 'name' is missing for "
                              "target %s in rule %s", target, each_rule)
                    continue
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
                    if 'value' not in result:
                        LOG.debug("Mandatory parameter 'value' is missing for "
                                  "target %s in rule %s", target, each_rule)
                        continue
                    action['hdr_action'][0]['action'] = 'HTTP_REPLACE_HDR'
                    action['hdr_action'][0]['hdr']['value'] = {}
                    action['hdr_action'][0]['hdr']['value']['val'] = result[
                                                                        'value']
                elif 'insert' in result:
                    if 'value' not in result:
                        LOG.debug("Mandatory parameter 'value' is missing for "
                                  "target %s in rule %s", target, each_rule)
                        continue
                    action['hdr_action'][0]['action'] = 'HTTP_ADD_HDR'
                    action['hdr_action'][0]['hdr']['value'] = {}
                    action['hdr_action'][0]['hdr']['value']['val'] = result[
                                                                        'value']
                else:
                    continue
            elif 'http-reply' in result:
                target = 'http-reply'
                if pol_type == 'request':
                    if 'redirect' in result:
                        if 'location' in result:
                            action = {
                                'redirect_action': {
                                   'keep_query': True,
                                   'path': {
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
                                   'status_code':
                                       "HTTP_REDIRECT_STATUS_CODE_302"
                                }
                            }
                        else:
                            LOG.debug("Mandatory parameter 'location' is "
                                      "missing for target %s in rule %s",
                                      target, each_rule)
                    else:
                        LOG.debug("Action not supported for target %s", target)
                else:
                    skip_event.append('response')
                    LOG.debug("Event 'response' not supported for target "
                              "'%s' in rule %s", target, each_rule)
            elif 'l7dos' in result:
                LOG.debug("Datascript %s", str(result))
            else:
                LOG.debug('Rule action %s not supported for rule %s',
                          str(result), each_rule)
            if target:
                skip_actions[each_rule].append(
                    {target: {'event': skip_event,
                              'parameter': skip_parameter,
                              'action': skip_action
                              }
                    })
            if action:
                action_list.append(action)
        return action_list, skip_actions


class PolicyConfigConvV11(PolicyConfigConv):
    def __init__(self, f5_policy_attributes, prefix):
        # self.supported_attr = f5_policy_attributes['']
        # self.ignore_for_value = f5_policy_attributes['']
        # self.unsupported_types = f5_policy_attributes['']
        # self.vs_na_attr = f5_policy_attributes['']
        # Added prefix for objects
        self.prefix = prefix


class PolicyConfigConvV10(PolicyConfigConv):
    def __init__(self, f5_policy_attributes, prefix):
        # self.supported_attr = f5_policy_attributes['']
        # self.ignore_for_value = f5_policy_attributes['']
        # self.unsupported_types = f5_policy_attributes['']
        # self.vs_na_attr = f5_policy_attributes['']
        # Added prefix for objects
        self.prefix = prefix
