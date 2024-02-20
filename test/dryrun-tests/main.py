# This is a sample Python script.
import zmap_test as ztest


# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def run_test():
    t = ztest.Test(port=80, num_of_ips=2)
    print(t.run())


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    run_test()
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
