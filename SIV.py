import os
import pwd
import grp
import csv
import time
import hashlib
import argparse
from datetime import datetime

from stat import (S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP,
                  S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH)


class Iteration(object):

    file_count = 0
    subdir_count = 0

    def __init__(self, report, verification, hash):
        self.csv_file = verification
        self.rep_file = report
        self.hash = hash
        self.fo_rep = open(self.rep_file, "a")
        # fo_ver = open(self.csv_file, 'wb'

    def create_csv_file(self):
        fo_ver = open(self.csv_file, 'wb')
        writer = csv.DictWriter(fo_ver,
                                fieldnames=["FULL_PATH", "FILE_SIZE", "USER", "GROUP", "MODE", "LAST_MODIFIED",
                                            "MD_OF_FILE"], delimiter=',')
        writer.writeheader()
        fo_ver.close()

    @staticmethod
    def md5(file_path):
        with open(file_path, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()

    @staticmethod
    def sha1(file_path):
        with open(file_path, 'rb') as fh:
            m = hashlib.sha1()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()

    @staticmethod
    def sha256(file_path, blocksize=4096):
        sha = hashlib.sha256()
        with open(file_path, 'rb') as fp:
            while 1:
                data = fp.read(blocksize)
                if data:
                    sha.update(data)
                else:
                    break
        return sha.hexdigest()

    @staticmethod
    def bit2int(bit):
        return int(oct(bit))

    def convert_st_mode(self, st_mode):
        bits = (S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH)
        mode = "%03d" % sum(int(bool(st_mode & bit)) * self.bit2int(bit) for bit in bits)
        return mode

    def get_unix_permissions(self, pth):
        mode = self.convert_st_mode(os.stat(pth).st_mode)
        return mode

    @staticmethod
    def get_absolute_path(root, item):
        absolute_path = os.path.abspath(os.path.join(root, item))
        return absolute_path

    @staticmethod
    def get_file_size(item):
        return os.path.getsize(item)

    @staticmethod
    def get_user_id(item):
        stat_info = os.stat(item)
        uid = stat_info.st_uid
        return uid

    @staticmethod
    def get_group_id(item):
        stat_info = os.stat(item)
        gid = stat_info.st_gid
        gid = grp.getgrgid(gid)[0]
        return gid

    def get_group_name(self, item):
        return pwd.getpwuid(self.get_user_id(item))[0]

    def write_to_csv_file(self, item):
        fo_ver = open(self.csv_file, 'a')
        csw_writer = csv.writer(fo_ver, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        csw_writer.writerow(item)
        fo_ver.close()

    def process_files(self, root, file_names, myhash):
        for f in file_names:
            absolute_path = self.get_absolute_path(root, f)

            # file size
            file_size = self.get_file_size(absolute_path)

            # Name of user owning the file
            user = self.get_group_name(absolute_path)

            # Name of group
            group = self.get_group_id(absolute_path)

            # access right to the file
            mode = self.get_unix_permissions(os.path.abspath(os.path.join(root, f)))

            # last modified time
            last_modified = os.path.getmtime(os.path.abspath(os.path.join(root, f)))

            # Message digest hash of the file
            if str(myhash) == "md5":
                md_of_file = self.md5(absolute_path)
            elif str(myhash) == "sha256":
                md_of_file = self.sha256(absolute_path)
            else:
                md_of_file = self.sha1(absolute_path)

            self.write_to_csv_file([absolute_path, user, group, mode, last_modified, md_of_file, file_size])

    def process_directories(self, root, dirs):
        for subdir in dirs:
            file_path = self.get_absolute_path(root, subdir)

            # Id and Name of user owning the file
            subdir_user = self.get_group_name(file_path)

            # group name
            subdir_group = self.get_group_id(file_path)

            # mode
            subdir_mode = self.get_unix_permissions(file_path)

            # modification time
            subdir_last_modified = os.path.getmtime(file_path)

            self.write_to_csv_file([file_path, subdir_user, subdir_group, subdir_mode, subdir_last_modified])

    def write_item_to_report_file(self, list):
            for item in list:
                self.fo_rep.write("%s\n" % item)

    def get_meta_data(self, path):
        for root, dirs, file_names in os.walk(path):
            # count files and dirs
            Iteration.file_count += len(file_names)
            Iteration.subdir_count += len(dirs)

            self.process_directories(root, dirs)
            # process files
            self.process_files(root, file_names, self.hash)


class Compare(Iteration):

    warning_counter = 0
    files_and_dirs = []

    @classmethod
    def update_warning_counter(cls, value):
        cls.warning_counter += value

    @classmethod
    def update_files_dirs(cls, value):
        cls.files_and_dirs.extend(value)

    def __init__(self, rep, ver, hash_type):
        super(Compare, self).__init__(rep, ver, hash_type)
        self.result = {}

    def dictionary_difference(self, current_dict, past_dict):
        set_current, set_past = set(current_dict.keys()), set(past_dict.keys())
        intersect = set_current.intersection(set_past)

        # check if files are added
        if len(set_current - intersect):
            self.update_files_dirs(["\n*************** Warning: FILES REMOVED************"])
            self.update_files_dirs(list(set_current - intersect))
            self.update_warning_counter(len(set_current - intersect))

        if len(set_past - intersect):
            self.update_files_dirs(["\n*************** Warning: FILES ADDED************"])
            self.update_files_dirs(list(set_past - intersect))
            self.update_warning_counter(len(set_past - intersect))

    def dictionary_compare(self, current_dict, past_dict, string):
        set_current, set_past = set(current_dict.keys()), set(past_dict.keys())
        intersect = set_current.intersection(set_past)
        if len(list(set(o for o in intersect if past_dict[o] != current_dict[o]))):
            self.update_files_dirs(["\n*************** Warning: " + string + " MODIFIED************"])
            self.update_files_dirs(list(set(o for o in intersect if past_dict[o] != current_dict[o])))
            self.update_warning_counter(len(set(o for o in intersect if past_dict[o] != current_dict[o])))

    def csv_as_dict(self, filename, delimiter=' '):

        reader = csv.reader(open(filename))
        for row in reader:
            key = row[0]
            if key in self.result:
                # implement your duplicate row handling here
                pass
            self.result[key] = row[1:]

        return self.result

    @staticmethod
    def parse_dictionary(dict, n):
        meta_data = {}
        for k, v in dict.iteritems():
            if len(v) == 6:
                meta_data[k] = v[n]
            else:
                pass
        return meta_data

    def analayze_metadata(self, iteration_dict, verification_dict):

        # check if hash value changed
        iteration_meta_data = self.parse_dictionary(iteration_dict, 5)
        verification_meta_data = self.parse_dictionary(verification_dict, 5)
        self.dictionary_compare(iteration_meta_data, verification_meta_data, "file size")

        # check if hash value changed
        iteration_meta_data = self.parse_dictionary(iteration_dict, 4)
        verification_meta_data = self.parse_dictionary(verification_dict, 4)
        self.dictionary_compare(iteration_meta_data, verification_meta_data, "hash value")

        # check if last modified date changes
        iteration_meta_data = self.parse_dictionary(iteration_dict, 3)
        verification_meta_data = self.parse_dictionary(verification_dict, 3)
        self.dictionary_compare(iteration_meta_data, verification_meta_data, "modification time")

        # check if access right changes
        iteration_meta_data = self.parse_dictionary(iteration_dict, 2)
        verification_meta_data = self.parse_dictionary(verification_dict, 2)
        self.dictionary_compare(iteration_meta_data, verification_meta_data, "access rights")

        # check if group name changes
        iteration_meta_data = self.parse_dictionary(iteration_dict, 1)
        verification_meta_data = self.parse_dictionary(verification_dict, 1)
        self.dictionary_compare(iteration_meta_data, verification_meta_data, "group name")

        # check if group name changes
        iteration_meta_data = self.parse_dictionary(iteration_dict, 0)
        verification_meta_data = self.parse_dictionary(verification_dict, 0)
        self.dictionary_compare(iteration_meta_data, verification_meta_data, "user name")


def main():
    parser = argparse.ArgumentParser(description="SIV")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", action="store_true")
    group.add_argument("-v", action="store_true")
    parser.add_argument("--dir", "-d", required=True,
                        help="This is the folder to be monitored")
    parser.add_argument("--ver", "-vf", required=True,
                        help="this is verification file)")
    parser.add_argument("--rep", "-r", required=True,
                        help="this is the report file)")
    parser.add_argument("--hash", "-H", required=True,
                        help="please provide the appropriate flags and arguments")

    args = parser.parse_args()

    if args.i:
        start_time = datetime.now()
        try:
            os.remove(args.rep)
        except OSError:
            pass
        itaration = Iteration(args.rep, args.ver, args.hash)
        itaration.create_csv_file()
        itaration.get_meta_data(args.dir)

        itaration.write_item_to_report_file(["\n\t\tINITIALIZATION "])
        itaration.write_item_to_report_file(["Monitored directory {}".format(args.dir)])
        itaration.write_item_to_report_file(["Verification file {}".format(args.ver)])
        itaration.write_item_to_report_file(["Number of iterated files are : {} "
                                            .format(Iteration.file_count)])
        itaration.write_item_to_report_file(["Number of iterated Directories are : {}"
                                            .format(Iteration.subdir_count)])
        itaration.write_item_to_report_file(["Time to finish INITIALIZATION {} seconds\n"
                                            .format(datetime.now()-start_time)])
        print ("\n\t\t**** ITERATION DONE ******\n")
        print "INITIALIZATION finished in,", (datetime.now() - start_time).total_seconds(), "seconds"

    elif args.v:
        start_time = datetime.now()
        print("the start time is , {}".format(time.time()))
        if not os.path.isfile(args.rep):
            exit("report file doesn't exit. First, run in -i mode instead")
        # we need to read the verification file from the iteration step. use class Compare
        verification = Compare(args.rep, args.ver, args.hash)
        dict_from_iteration_step = verification.csv_as_dict(args.ver)

        # it is now time to go through the target directory and verify the changes.
        # verification step is nothing but iteration + comparision.
        # here is the iteration
        verification.create_csv_file()
        verification.get_meta_data(args.dir)

        verification.write_item_to_report_file(["\n\t\tVERIFICATION "])
        verification.write_item_to_report_file(["Monitored directory {}".format(args.dir)])
        verification.write_item_to_report_file(["Verification file {}".format(args.ver)])
        verification.write_item_to_report_file(["Number of iterated files are : {} "
                                               .format(verification.file_count)])
        verification.write_item_to_report_file(["Number of iterated Directories are : {}"
                                               .format(verification.subdir_count)])
        verification.write_item_to_report_file(["Time to finish VERIFICATION {} seconds"
                                               .format(datetime.now() - start_time)])

        # here is the comparision
        verify = Compare(args.rep, args.ver, args.hash)
        dict_from_verification_step = verify.csv_as_dict(args.ver)
        verification.dictionary_difference(dict_from_iteration_step, dict_from_verification_step)
        verification.analayze_metadata(dict_from_iteration_step, dict_from_verification_step)
        verification.write_item_to_report_file(["Number of warnings {} \n".format(Compare.warning_counter)])
        verification.write_item_to_report_file(Compare.files_and_dirs)

        print ("\n\t\t**** VERIFICATION DONE ****\n\n please check {} file in {}\n"
               .format(args.rep, os.path.abspath(args.rep)))
        print "Verification finished in,", (datetime.now() - start_time).total_seconds(), "seconds"


if __name__ == "__main__":
    main()
