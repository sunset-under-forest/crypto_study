s_box = {0: 0x6, 1: 0x4, 2: 0xc, 3: 0x5, 4: 0x0, 5: 0x7, 6: 0x2, 7: 0xe, 8: 0x1, 9: 0xf, 10: 0x3, 11: 0xd, 12: 0x8,
         13: 0xa, 14: 0x9, 15: 0xb}
s_box_inv = dict(i[::-1] for i in s_box.items())


def cipherONE(m, k: list):
    assert len(k) == 2
    return s_box[m ^ k[0]] ^ k[1]


def dif_table(s_box):
    # 生成差分表
    t = []
    for in_diff in range(16):
        tmp = [0] * 16
        for i in range(16):
            tmp[s_box[i] ^ s_box[i ^ in_diff]] += 1
        t.append(tmp)
    return t


def study():
    key = [2, 7]  # unknown
    m_list = [i for i in range(16)]
    c_list = [cipherONE(i, key) for i in m_list]
    print([m_list[i] ^ m_list[0xf - i] for i in range(16)])
    print([c_list[i] ^ c_list[0xf - i] for i in range(16)])
    s = [s_box[i] for i in range(16)]
    print(dif_table(s_box))
    # 可知cipherONE 的过程 m ---k0---> u ---s_box---> v ---k1---> c
    m0 = m_list[0]
    m1 = m_list[0xf - 0]
    c0 = c_list[0]
    c1 = c_list[0xf - 0]
    temp0 = []
    # 首先爆破k1，可知 u = s_box_inv[k1 ^ c]
    # 可知我们的输入差分 in_diff = 0xf，因此查看每个k1，并通过判断 u0 ^ u1 == in_diff 来筛选密钥
    in_diff = 0xf
    for k1 in range(16):
        u0 = s_box_inv[k1 ^ c0]
        u1 = s_box_inv[k1 ^ c1]
        if u0 ^ u1 == in_diff:
            temp0.append(k1)

    print(temp0)  # [1, 7]
    # 通过第一组数据筛出了k1有可能是1或7
    # 开始测试第二组数据
    m0 = m_list[1]
    m1 = m_list[0xf - 1]
    c0 = c_list[1]
    c1 = c_list[0xf - 1]
    temp1 = []
    in_diff = 0xf
    for k1 in range(16):
        u0 = s_box_inv[k1 ^ c0]
        u1 = s_box_inv[k1 ^ c1]
        if u0 ^ u1 == in_diff:
            temp1.append(k1)

    print(temp1)  # [0, 2, 4, 6, 7, 9, 10, 11, 13, 15]
    # 通过第二组和第一组结果的交集可以看出，k1等于7
    k1 = 7
    # 那么如何通过k1求出k0呢？
    # 由加密过程（m ---k0---> u ---s_box---> v ---k1---> c）可知
    # 有了k1 就有了u ，所以k0 = m ^ u
    # 解出k1
    u0 = s_box_inv[k1 ^ c0]
    k0 = m0 ^ u0
    print(k0)  # 2
    # 可知key = [2,7]


# 以下是自动脚本
def find_keys(c0, c1, in_diff):
    temp = set()
    for k in range(16):
        u0 = s_box_inv[k ^ c0]
        u1 = s_box_inv[k ^ c1]
        if u0 ^ u1 == in_diff:
            temp.add(k)
    return temp


def find_k1(c_set, in_diff=0xf):
    # c_set 是一个包含多个二元组的列表，每个二元组代表一对c0，c1，它们对应的m0，m1的差分是in_diff

    k1_set = find_keys(c_set[0][0], c_set[0][1], in_diff)
    for i in range(1, len(c_set)):
        c0, c1 = c_set[i]
        k1_set &= find_keys(c0, c1, in_diff)
    return k1_set

def find_k0(m,c,k1):
    return s_box_inv[c^k1] ^ m

def crack():
    from random import randint
    key = [randint(0, 15) for _ in range(2)]
    print(f"key(unknown) = {key}")
    m_list = [i for i in range(16)]
    c_list = [cipherONE(i, key) for i in m_list]
    c_set = [(c_list[i], c_list[0xf - i]) for i in range(8)]

    k1 = find_k1(c_set)
    if not k1:
        print("find k1 failed!")
        return
    k1 = k1.pop()
    k0 = find_k0(m_list[0],c_list[0],k1)
    key = [k0,k1]
    print(f"KEY FOUND!\nKEY = {key}")


if __name__ == '__main__':
    crack()
