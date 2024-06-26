import datetime

import volatility3.framework.layers.scanners as scan
from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers
from volatility3.framework.exceptions import PagedInvalidAddressException

import volatility3.plugins.sqlite_help as sqlite_help

FORWARD = sqlite_help.FORWARD
BACKWARD = sqlite_help.BACKWARD

class FireFoxHistory(interfaces.plugins.PluginInterface):
    """ Scans for and parses potential Firefox url history"""
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", 
                description="Memory layer for the kernel", 
                architectures=["Intel32", "Intel64"]
            ),
            requirements.BooleanRequirement(
                name="nulltime", 
                description="Don't print entries with null timestamps", 
                default=False, 
                optional=True
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        physical_layer_name = self.context.layers[kernel.layer_name].config.get(
            "memory_layer", None
        )
        layer = self.context.layers[physical_layer_name]
        needles=[
                    b'\x06\x25',
                    b'\x00\x25',
                ]
        urls = {}
        
        for offset, _value in layer.scan(
            context=self.context,
            scanner=scan.MultiStringScanner(patterns=needles),
        ):
            try:
                ff_buff = layer.read(offset - 21, 3000)
            except PagedInvalidAddressException as e:
                print(f"Unable to read page at offset {offset}: {e}")
                continue

            start = 21
            
            foreign_count_length = 0
            foreign_count = "N/A"

            if ff_buff[start-1] in (1, 2, 8, 9):
                start -= 1
                (frecency_length, frecency) = sqlite_help.varint_type_to_length(ff_buff[start])
            else:
                continue

            if ff_buff[start-1] in (0, 1, 8, 9):
                start -= 1
                (favicon_id_length, favicon_id) = sqlite_help.varint_type_to_length(ff_buff[start])
            else:
                continue

            if ff_buff[start-1] not in (8, 9):
                continue
            start -= 1
            (typed_length, typed) = sqlite_help.varint_type_to_length(ff_buff[start])

            if ff_buff[start-1] not in (8, 9):
                continue
            start -= 1
            (hidden_length, hidden) = sqlite_help.varint_type_to_length(ff_buff[start])

            if ff_buff[start-1] in (1, 8, 9):
                start -= 1
                (visit_count_length, visit_count) = sqlite_help.varint_type_to_length(ff_buff[start])
            else:
                continue

            start -= 1
            (rev_host_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            rev_host_length = sqlite_help.varint_to_text_length(rev_host_length)

            start -= varint_len
            (title_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            title_length = sqlite_help.varint_to_text_length(title_length)
            
            start -= varint_len
            (url_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            url_length = sqlite_help.varint_to_text_length(url_length)
            
            start -= varint_len
            url_id_length = ff_buff[start]
            start -= 1
            payload_header_length = ff_buff[start]            
            payload_header_end = start + payload_header_length

            start -= 1
            (row_id, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            
            if row_id < 0:
                continue

            start -= varint_len
            if start < 0:
                continue
            (payload_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            if payload_length < 6:
                continue

            (last_visit_date_length, last_visit_date) = sqlite_help.varint_type_to_length(ff_buff[21])
            (guid_length, varint_len) = sqlite_help.find_varint(ff_buff, 22, FORWARD)
            guid_length = sqlite_help.varint_to_text_length(guid_length)
            start = 22 + varint_len

            if start != payload_header_end:
                (foreign_count_length, foreign_count) = sqlite_help.varint_type_to_length(ff_buff[start])
                start += 1

            url_id = sqlite_help.sql_unpack(ff_buff[start:start+url_id_length])

            url_length = int(url_length)
            title_length = int(title_length)
            rev_host_length = int(rev_host_length)
            guid_length = int(guid_length)

            start += url_id_length
            url = ff_buff[start:start + url_length]
            url = url.decode('utf-8', errors='ignore')

            start += url_length
            title = ff_buff[start:start + title_length]
            title = title.decode('utf-8', errors='ignore')

            start += title_length
            rev_host = ff_buff[start:start+rev_host_length]

            start += rev_host_length
            if visit_count_length > 0:
                visit_count = sqlite_help.sql_unpack(ff_buff[start:start+visit_count_length])

            start += visit_count_length
            if hidden_length > 0:
                hidden = sqlite_help.sql_unpack(ff_buff[start:start+hidden_length])

            start += hidden_length
            if typed_length > 0:
                typed = sqlite_help.sql_unpack(ff_buff[start:start+typed_length])

            start += typed_length
            favicon_id = ""
            if favicon_id_length > 0:
                favicon_id = sqlite_help.sql_unpack(ff_buff[start:start+favicon_id_length])

            start += favicon_id_length
            if frecency_length > 0:
                frecency = sqlite_help.sql_unpack(ff_buff[start:start+frecency_length])

            start += frecency_length
            last_visit_date = ff_buff[start:start+last_visit_date_length]
            last_visit_date = sqlite_help.sql_unpack(last_visit_date)
            if last_visit_date_length == 8 and last_visit_date < 0:
                continue
            if str(last_visit_date) > str(1) and last_visit_date:
                last_visit_date = sqlite_help.get_nixtime_from_msec(last_visit_date)
            if last_visit_date_length == 8 and type(last_visit_date) is datetime and last_visit_date.year == 1970:
                continue

            start += last_visit_date_length
            guid = ff_buff[start:start+guid_length]

            start += guid_length
            if foreign_count_length > 0:
                foreign_count = sqlite_help.sql_unpack(ff_buff[start:start+foreign_count_length])
                start += foreign_count_length
                
            urls[int(offset)] = (int(row_id), str(url), str(title), int(visit_count), int(typed), str(last_visit_date))
            
        seen_tuples = set()
        for value in urls.values():
            if value not in seen_tuples:
                seen_tuples.add(value)
                yield 0, (value[0], value[1], value[2], value[3], value[4], value[5])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Index", int), 
                ("URL", str), 
                ("Title", str), 
                ("Visit Count", int),
                ("Typed Count", int), 
                ("Last Visit Time", str)
            ], 
            self._generator()
        )
    

class FireFoxDownloads(interfaces.plugins.PluginInterface):
    """ Scans for and parses potential Firefox download records -- downloads.sqlite moz_downloads table pre FF26 only"""
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", 
                description="Memory layer for the kernel", 
                architectures=["Intel32", "Intel64"]
            ),
            requirements.BooleanRequirement(
                name="nulltime", 
                description="Don't print entries with null timestamps", 
                default=False, 
                optional=True
            ),
        ]
    
    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        physical_layer_name = self.context.layers[kernel.layer_name].config.get(
            "memory_layer", None
        )
        layer = self.context.layers[physical_layer_name]
        needles=[
                    b'\x06\x06\x08',
                    b'\x06\x06\x09',
                ]
        downloads = {}
        
        for offset, _value in layer.scan(
            context=self.context,
            scanner=scan.MultiStringScanner(patterns=needles),
        ):
            try:
                ff_buff = layer.read(offset - 16, 3000)
            except PagedInvalidAddressException as e:
                print(f"Unable to read page at offset {offset}: {e}")
                continue

            start = 16
            
            good = False

            start -= 1
            (tempPath_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            tempPath_length = sqlite_help.varint_to_text_length(tempPath_length)

            # work backward from the start of the needle to the first field payload_length
            start -= varint_len
            (target_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            target_length = sqlite_help.varint_to_text_length(target_length)

            start -= varint_len
            (source_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            source_length = sqlite_help.varint_to_text_length(source_length)

            start -= varint_len
            (name_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            name_length = sqlite_help.varint_to_text_length(name_length)

            start -= varint_len
            (id_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            start -= varint_len
            (payload_header_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            start -= varint_len
            (row_id, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            start -= varint_len
            (payload_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            # jump back to the needle, startTime_length
            start = 16

            # get all of the single byte lengths around the needle
            (startTime_length, startTime) = sqlite_help.varint_type_to_length(ff_buff[start])
            (endTime_length, endTime) = sqlite_help.varint_type_to_length(ff_buff[start+1])
            (state_length, state) = sqlite_help.varint_type_to_length(ff_buff[start+2])

            # get the rest of the fields in the row moving forward
            start = 19
            (referrer_length, varint_len) = sqlite_help.find_varint(ff_buff, start, FORWARD)
            referrer_length = sqlite_help.varint_to_text_length(referrer_length)
            start += varint_len

            (entityID_length, varint_len) = sqlite_help.find_varint(ff_buff, start, FORWARD)
            entityID_length = sqlite_help.varint_to_text_length(entityID_length)
            start += varint_len

            (currBytes_length, currBytes) = sqlite_help.varint_type_to_length(ff_buff[start])
            (maxBytes_length, maxBytes) = sqlite_help.varint_type_to_length(ff_buff[start+1])

            start += 2

            (mimeType_length, varint_len) = sqlite_help.find_varint(ff_buff, start, FORWARD)
            mimeType_length = sqlite_help.varint_to_text_length(mimeType_length)
            start += varint_len

            (preferredApplication_length, varint_len) = sqlite_help.find_varint(ff_buff, start, FORWARD)
            preferredApplication_length = sqlite_help.varint_to_text_length(preferredApplication_length)
            start += varint_len

            (preferredAction_length, preferredAction) = sqlite_help.varint_type_to_length(ff_buff[start])
            (autoResume_length, autoResume) = sqlite_help.varint_type_to_length(ff_buff[start+1])

            start += 2

            name_length = int(name_length)
            source_length = int(source_length)
            target_length = int(target_length)
            tempPath_length = int(tempPath_length)
            startTime_length = int(startTime_length)
            endTime_length = int(endTime_length)
            state_length = int(state_length)
            referrer_length = int(referrer_length)
            entityID_length = int(entityID_length)
            currBytes_length = int(currBytes_length)
            maxBytes_length = int(maxBytes_length)
            mimeType_length = int(mimeType_length)
            preferredApplication_length = int(preferredApplication_length)
            preferredAction_length = int(preferredAction_length)
            autoResume_length = int(autoResume_length)
            
            name = ff_buff[start:start+name_length]
            start += name_length
            if type(name) is bytes:
                name = name.decode('utf-8', errors='ignore')

            source = ff_buff[start:start+source_length]
            start += source_length
            if type(source) is bytes:
                source = source.decode('utf-8', errors='ignore')

            target = ff_buff[start:start+target_length]
            start += target_length
            if type(target) is bytes:
                target = target.decode('utf-8', errors='ignore')

            tempPath = ff_buff[start:start+tempPath_length]
            start += tempPath_length
            if type(tempPath) is bytes:
                tempPath = tempPath.decode('utf-8', errors='ignore')

            # do some checks on the startTime/endTime to make sure they are valid
            startTime = ff_buff[start:start+startTime_length]
            startTime = sqlite_help.sql_unpack(startTime)
            if str(startTime) > str(0) and startTime:
                startTime = sqlite_help.get_nixtime_from_msec(startTime)
            if type(startTime) is not datetime:
                continue
            start += startTime_length

            endTime = ff_buff[start:start+endTime_length]
            endTime = sqlite_help.sql_unpack(endTime)
            if str(endTime) > str(0) and startTime:
                endTime = sqlite_help.get_nixtime_from_msec(endTime)
            if type(endTime) is not datetime:
                continue
            start += endTime_length

            # if both dates are 1970, it's probably a bad record and not very useful, so skip
            # if only 1 is 1970, print it because it may be an old record with one valid date
            if startTime.year == 1970 and endTime.year == 1970:
                continue

            if state_length > 0:
                state = sqlite_help.sql_unpack(ff_buff[start:start+state_length])
            start += state_length
            if type(state) is bytes:
                state = state.decode('utf-8', errors='ignore')

            referrer = ff_buff[start:start+referrer_length]
            start += referrer_length
            if type(referrer) is bytes:
                referrer = referrer.decode('utf-8', errors='ignore')

            entityID = ff_buff[start:start+entityID_length]
            start += entityID_length
            if type(entityID) is bytes:
                entityID = entityID.decode('utf-8', errors='ignore')

            currBytes = ff_buff[start:start+currBytes_length]
            currBytes = sqlite_help.sql_unpack(currBytes)
            # skip if negative or greater than 1TB
            if currBytes < 0 or currBytes > 1000000000000:
                continue
            start += currBytes_length
            if type(currBytes) is bytes:
                currBytes = currBytes.decode('utf-8', errors='ignore')

            maxBytes = ff_buff[start:start+maxBytes_length]
            maxBytes = sqlite_help.sql_unpack(maxBytes)
            # skip if negative or greater than 1TB
            if maxBytes < 0 or maxBytes > 1000000000000:
                continue
            start += maxBytes_length
            if type(maxBytes) is bytes:
                maxBytes = maxBytes.decode('utf-8', errors='ignore')

            mimeType = ff_buff[start:start+mimeType_length]
            start += mimeType_length
            if type(mimeType) is bytes:
                mimeType = mimeType.decode('utf-8', errors='ignore')

            preferredApplication = ff_buff[start:start+preferredApplication_length]
            start += preferredApplication_length
            if type(preferredApplication) is bytes:
                preferredApplication = preferredApplication.decode('utf-8', errors='ignore')

            # these fields can have a value 0x8 or 0x9 in the length field
            # in that case, the "data" portion is not there, and the value is impled 
            # to be 0 or 1, respectively
            if preferredAction_length > 0:
                preferredAction = ff_buff[start:start+preferredAction_length]
                preferredAction = sqlite_help.sql_unpack(preferredAction)
            start += preferredAction_length
            if type(preferredAction) is bytes:
                preferredAction = preferredAction.decode('utf-8', errors='ignore')
                
            if autoResume_length > 0:
                autoResume = ff_buff[start:start+autoResume_length]
                autoResume = sqlite_help.sql_unpack(autoResume)
            start += autoResume_length
            if type(autoResume) is bytes:
                autoResume = autoResume.decode('utf-8', errors='ignore')

            #downloads[int(offset)] = (row_id, name, source, target, tempPath, startTime, endTime, state, referrer, entityID, currBytes, maxBytes, mimeType, preferredApplication, preferredAction, autoResume)
            downloads[int(offset)] = (int(row_id), str(name), str(source), str(target), str(tempPath), datetime(startTime), datetime(endTime), int(state), str(referrer), str(entityID), str(currBytes), str(maxBytes), str(mimeType), str(preferredApplication), str(preferredAction), str(autoResume))


            # add all the fields to a tuple so we only print a unique record once
            seen_tuples = set()
        for value in downloads.values():
            if value not in seen_tuples:
                seen_tuples.add(value)
                yield 0, (value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Row Id", int), 
                ("Name", str), 
                ("Source", str), 
                ("Target", str),
                ("Temp Path", str), 
                ("Start Time", datetime.datetime),
                ("End Time", datetime.datetime),
                ("State", int),
                ("Referrer", str), 
                ("Entity Id", str), 
                ("Current Bytes", str), 
                ("Max Bytes", str),
                ("MIME Type", str),
                ("Prefer App", str),
                ("Prefer Action", str),
                ("Auto Resume", str)
            ], 
            self._generator()
        )