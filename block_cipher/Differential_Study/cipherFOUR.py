s_box = {0: 0x6, 1: 0x4, 2: 0xc, 3: 0x5, 4: 0x0, 5: 0x7, 6: 0x2, 7: 0xe, 8: 0x1, 9: 0xf, 10: 0x3, 11: 0xd, 12: 0x8,
         13: 0xa, 14: 0x9, 15: 0xb}
s_box_inv = dict(i[::-1] for i in s_box.items())
from cipherTWO import find_k2, find_k1, find_k0
from cipherTHREE import find_k3


def cipherFOUR(m, k: list):
    assert len(k) == 5
    return s_box[s_box[s_box[s_box[m ^ k[0]] ^ k[1]] ^ k[2]] ^ k[3]] ^ k[4]


def dif_map(s_box, in_diff):
    # 生成差分对应表
    t = {}
    for i in range(16):
        t[s_box[i] ^ s_box[i ^ in_diff]] = t.get(s_box[i] ^ s_box[i ^ in_diff], 0) + 1
    return t


def study():
    key = [2, 7, 11, 14, 3]  # unknown
    m_list = [i for i in range(16)]
    c_list = [cipherFOUR(i, key) for i in m_list]
    print([m_list[i] ^ m_list[0xf - i] for i in range(16)])
    print([c_list[i] ^ c_list[0xf - i] for i in range(16)])
    s = [s_box[i] for i in range(16)]
    # 可知cipherTHREE 的过程 m ---k0---> u ---s_box---> v ---k1---> w ---s_box---> x ---k2---> y ---s_box---> z ---k3--->
    # a ---s_box---> b ---k4---> c
    # 不多说了，直接看脚本，原理一样，只是范围又变大了，基本上再多轮的变换就是空间会大点，但是好像经过测试在k2的地方基本上就确定了，也就是说差分攻击好像确实挺屌的


# 自动脚本

def find_keys(c0, c1, probable_out_diff0):
    probable_out_diff = set()
    for out_diff0 in probable_out_diff0:
        for out_diff1 in dif_map(s_box, out_diff0).keys():
            for pod in dif_map(s_box, out_diff1).keys():
                probable_out_diff.add(pod)
    key_list = set()
    for k2 in range(16):
        w0 = s_box_inv[k2 ^ c0]
        w1 = s_box_inv[k2 ^ c1]
        if w0 ^ w1 in probable_out_diff:
            key_list.add(k2)
    return key_list


def find_k4(c_set, in_diff=0xf):
    probable_out_diff0 = list(dif_map(s_box, in_diff).keys())
    k3_set = find_keys(c_set[0][0], c_set[0][1], probable_out_diff0)
    for i in range(1, len(c_set)):
        c0, c1 = c_set[i]
        k3_set &= find_keys(c0, c1, probable_out_diff0)
    return k3_set


def verify(m_list, c_list, key):
    return c_list == [cipherFOUR(i, key) for i in m_list]


def crack():
    from random import randint
    key = [randint(0, 15) for _ in range(5)]
    print(f"key(unknown) = {key}")
    m_list = [i for i in range(16)]
    c_list = [cipherFOUR(i, key) for i in m_list]
    c_set = [(c_list[i], c_list[(0xf - i)]) for i in range(8)]
    k4_list = find_k4(c_set)
    for k4 in k4_list:
        c_set_for_k3 = [(s_box_inv[c_list[i] ^ k4], s_box_inv[c_list[0xf - i] ^ k4]) for i in range(8)]
        k3_list = find_k3(c_set_for_k3)
        for k3 in k3_list:
            c_set_for_k2 = [(s_box_inv[s_box_inv[c_list[i] ^ k4] ^ k3], s_box_inv[s_box_inv[c_list[0xf - i] ^ k4] ^ k3])
                            for i in range(8)]
            k2_list = find_k2(c_set_for_k2)
            for k2 in k2_list:
                c_set_for_k1 = [
                    (s_box_inv[s_box_inv[s_box_inv[c_list[i] ^ k4] ^ k3] ^ k2],
                     s_box_inv[s_box_inv[s_box_inv[c_list[0xf - i] ^ k4] ^ k3] ^ k2])
                    for i in range(8)]
                k1_list = find_k1(c_set_for_k1)
                for k1 in k1_list:
                    k0 = find_k0(m_list[0], s_box_inv[s_box_inv[s_box_inv[c_list[0] ^ k4] ^ k3] ^ k2], k1)
                    key = [k0, k1, k2, k3, k4]
                    if verify(m_list, c_list, key):
                        print(f"KEY FOUND!\nKEY = {key}")
                        return


if __name__ == '__main__':
    crack()
