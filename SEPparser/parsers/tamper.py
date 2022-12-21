import helpers.enums as enums


def parse_tamper_protect(logData, logEntry, fname):
    # need action

    action = ''
    time = logData[0]
    computer = logData[4]
    user = logData[5]
    event = enums.event_301.get(int(logData[23]) if logData[23] else '', str('","'+logData[23]))
    actor = f'{logData[21]} (PID {logData[19]})'
    targetprocess = f'{logData[29]} (PID {logData[25]})'
    target = logData[27]

    return (f'"{fname}","{computer}","{user}","{action}","{event}","{actor}","{target}","{targetprocess}","{time}\n')
