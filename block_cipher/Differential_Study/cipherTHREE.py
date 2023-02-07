s_box = {0: 0x6, 1: 0x4, 2: 0xc, 3: 0x5, 4: 0x0, 5: 0x7, 6: 0x2, 7: 0xe, 8: 0x1, 9: 0xf, 10: 0x3, 11: 0xd, 12: 0x8,
         13: 0xa, 14: 0x9, 15: 0xb}
s_box_inv = dict(i[::-1] for i in s_box.items())
from cipherTWO import find_k2,find_k1,find_k0


def cipherTHREE(m, k: list):
    assert len(k) == 4
    return s_box[s_box[s_box[m ^ k[0]] ^ k[1]] ^ k[2]] ^ k[3]


def dif_map(s_box, in_diff):
    # 生成差分对应表
    t = {}
    for i in range(16):
        t[s_box[i] ^ s_box[i ^ in_diff]] = t.get(s_box[i] ^ s_box[i ^ in_diff], 0) + 1
    return t


def study():
    key = [2, 7, 11, 14]  # unknown
    m_list = [i for i in range(16)]
    c_list = [cipherTHREE(i, key) for i in m_list]
    print([m_list[i] ^ m_list[0xf - i] for i in range(16)])
    print([c_list[i] ^ c_list[0xf - i] for i in range(16)])
    s = [s_box[i] for i in range(16)]
    # 可知cipherTHREE 的过程 m ---k0---> u ---s_box---> v ---k1---> w ---s_box---> x ---k2---> y ---s_box---> z ---k3---> c
    idx = 0
    m0 = m_list[idx]
    m1 = m_list[0xf - idx]
    c0 = c_list[idx]
    c1 = c_list[0xf - idx]
    # 同理，查看差分表预测出第一次s_box的输出差分（也就是v的差分）后就是一个cipherTWO的问题
    # 说白了就是密钥空间大了一段，分支更多了
    # 我们查看输入差分为0xf的输出差分次数对应表
    in_diff = 0xf
    print(dif_map(s_box, in_diff))  # {13: 10, 6: 2, 4: 2, 15: 2}
    # 这里的[13, 6, 4, 15]是第一个s_box的输出差分，也是第二个s_box的输入差分，对每个可能输入差分再进行一次预测输出差分
    # 然后一样先解出最接近c的k3，得到的k3的范围稍微会大一点，后面就遍历每个k3，然后像cipherTWO一样解出每个ki后进行验证即可
    # 具体的见下面的自动脚本

# 自动脚本

def find_keys(c0, c1, probable_out_diff0):
    probable_out_diff = []
    for in_diff in probable_out_diff0:
        for pod in dif_map(s_box, in_diff).keys():
            probable_out_diff.append(pod)
    key_list = set()
    for k2 in range(16):
        w0 = s_box_inv[k2 ^ c0]
        w1 = s_box_inv[k2 ^ c1]
        if w0 ^ w1 in probable_out_diff:
            key_list.add(k2)
    return key_list


def find_k3(c_set, in_diff=0xf):
    probable_out_diff0 = list(dif_map(s_box, in_diff).keys())
    k3_set = find_keys(c_set[0][0], c_set[0][1], probable_out_diff0)
    for i in range(1, len(c_set)):
        c0, c1 = c_set[i]
        k3_set &= find_keys(c0, c1, probable_out_diff0)
    return k3_set


def verify(m_list, c_list, key):
    return c_list == [cipherTHREE(i, key) for i in m_list]


def crack():
    from random import randint
    key = [randint(0, 15) for _ in range(4)]
    print(f"key(unknown) = {key}")
    m_list = [i for i in range(16)]
    c_list = [cipherTHREE(i, key) for i in m_list]
    c_set = [(c_list[i], c_list[(0xf - i)]) for i in range(8)]
    k3_list = find_k3(c_set)
    for k3 in k3_list:
        c_set_for_k2 = [(s_box_inv[c_list[i] ^ k3], s_box_inv[c_list[0xf - i] ^ k3]) for i in range(8)]
        k2_list = find_k2(c_set_for_k2)
        for k2 in k2_list:
            c_set_for_k1 = [(s_box_inv[s_box_inv[c_list[i] ^ k3] ^ k2], s_box_inv[s_box_inv[c_list[0xf - i] ^ k3] ^ k2])
                            for i in range(8)]
            k1_list = find_k1(c_set_for_k1)
            for k1 in k1_list:
                k0 = find_k0(m_list[0], s_box_inv[s_box_inv[c_list[0] ^ k3] ^ k2], k1)
                key = [k0, k1, k2,k3]
                if verify(m_list, c_list, key):
                    print(f"KEY FOUND!\nKEY = {key}")
                    return


if __name__ == '__main__':
    crack()
