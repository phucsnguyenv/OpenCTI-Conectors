import os
import shutil
import csv
import time

_data_path = os.path.dirname(os.path.abspath(__file__))+"/data"


def _process_message(data):
    indicators = []
    _valid = 0
    for row in data:
        if(row[0] == "_report"):
            report = row
            _valid = 1
        else:
            indicators.append(create_indicator(row))
    if(_valid):
        print(create_report(report))
        for ind in indicators:
            print(ind)
    else:
        print("Cant find any report, add it to csv file")


def create_report(row):
    row.append("report added")
    return row


def create_indicator(row):
    row.append("indicator added")
    return row


def _archive_file(data):
    _src = data
    _dest = _data_path+'/archive'
    shutil.move(_src, _dest)


def _read_file(data):
    with open(data, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        _process_message(reader)
        # _archive_file(data)


while True:
    _list_files = os.listdir(_data_path+'/files')
    if (_list_files.__len__() > 1):
        for data_file in _list_files:
            if(data_file != "sample.csv"):
                data_file = _data_path+'/files/'+data_file
                _read_file(data_file)
    else:
        print("no file")
    time.sleep(10)
