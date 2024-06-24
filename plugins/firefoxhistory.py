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
                
            urls[int(offset)] = (int(row_id),
            str(url), str(title), int(visit_count), int(typed), str(last_visit_date))
            
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