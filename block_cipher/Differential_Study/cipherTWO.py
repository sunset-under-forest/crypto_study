s_box = {0: 0x6, 1: 0x4, 2: 0xc, 3: 0x5, 4: 0x0, 5: 0x7, 6: 0x2, 7: 0xe, 8: 0x1, 9: 0xf, 10: 0x3, 11: 0xd, 12: 0x8,
         13: 0xa, 14: 0x9, 15: 0xb}
s_box_inv = dict(i[::-1] for i in s_box.items())
from cipherONE import find_k0, find_k1


def cipherTWO(m, k: list):
    assert len(k) == 3
    return s_box[s_box[m ^ k[0]] ^ k[1]] ^ k[2]


def dif_map(s_box, in_diff):
    # 生成差分对应表
    t = {}
    for i in range(16):
        t[s_box[i] ^ s_box[i ^ in_diff]] = t.get(s_box[i] ^ s_box[i ^ in_diff], 0) + 1
    return t


def study():
    key = [2, 7, 11]  # unknown
    m_list = [i for i in range(16)]
    c_list = [cipherTWO(i, key) for i in m_list]
    print([m_list[i] ^ m_list[0xf - i] for i in range(16)])
    print([c_list[i] ^ c_list[0xf - i] for i in range(16)])
    s = [s_box[i] for i in range(16)]
    # 可知cipherTWO 的过程 m ---k0---> u ---s_box---> v ---k1---> w ---s_box---> x ---k2---> c
    idx = 0
    m0 = m_list[idx]
    m1 = m_list[0xf - idx]
    c0 = c_list[idx]
    c1 = c_list[0xf - idx]
    # 首先爆破k2，可知 x = s_box_inv[k2 ^ c]
    # 上一道题可以直接确定我们爆破的k2是否正确，但是现在我们没有v的值，所以无法判断k2的正确与否
    # 不过，现在的我们可以预测v的值，这就是差分分析的作用，因为这个s_box是有问题的，所以预测也很简单
    # 首先知道输入差分in_diff = 0xf
    in_diff = 0xf
    # 我们查看输入差分为0xf的输出差分次数对应表
    print(dif_map(s_box, in_diff))  # {13: 10, 6: 2, 4: 2, 15: 2}
    # 可见输出差分对应的只有四种情况，相对比于爆破k0（十六种情况），要尝试的密钥空间减少了75% ！
    # 也就是说我们爆破k2，得出的w = s_box_inv[c ^ k2]
    # w0 ^ w1 只有上述四种可能值 [13, 6, 4, 15]
    temp = list(dif_map(s_box, in_diff).keys())
    k2_list = set()
    for k2 in range(16):
        w0 = s_box_inv[k2 ^ c0]
        w1 = s_box_inv[k2 ^ c1]
        if w0 ^ w1 in temp:
            k2_list.add(k2)
    print(k2_list)  # {10, 11, 12, 13}
    # 换一组数据继续
    idx = 2
    m0 = m_list[idx]
    m1 = m_list[0xf - idx]
    c0 = c_list[idx]
    c1 = c_list[0xf - idx]
    k2_list_another = set()
    for k2 in range(16):
        w0 = s_box_inv[k2 ^ c0]
        w1 = s_box_inv[k2 ^ c1]
        if w0 ^ w1 in temp:
            k2_list_another.add(k2)
    k2_list &= k2_list_another
    print(k2_list)  # {10, 11}
    # 为什么不选idx = 1 因为测试过idx=1的时候求出的k2范围和idx = 0一样，所以略过
    # 换一组数据继续...发现其他数据都无法再缩小范围了
    # 所以k2还是无法验证，需要最后结合密钥验证，不过范围已经很小很小了
    # 有了k2就跟cipherONE一样了，把cipherONE的find_k0，find_k1方法拿过来解出对应的k0,k1

    # k2 = 10的时候
    k2 = 10
    c_set = [(s_box_inv[c_list[i] ^ k2], s_box_inv[c_list[0xf - i] ^ k2]) for i in range(8)]
    k1 = find_k1(c_set)
    k0 = find_k0(m_list[0], s_box_inv[c_list[0] ^ k2], k1)
    crack_key = [k0, k1, k2]
    print(crack_key)  # [3, 7, 10]
    # 现在我们有了一组key，但是要验证正确性（因为还有别的情况，而真实情况只有一种）
    # 验证很简单，重新用这组key加密看密文是否匹配就行了
    print(c_list == [cipherTWO(i, crack_key) for i in m_list])  # False
    # 两个列表不相同，所以key不对（注：python列表的==运算符应该是逐一对列表内的元素使用==运算符，所以这里可以用来判断结果是否相同）

    # 现在我们看一下k2 = 11的时候
    k2 = 11
    c_set = [(s_box_inv[c_list[i] ^ k2], s_box_inv[c_list[0xf - i] ^ k2]) for i in range(8)]
    k1 = find_k1(c_set)
    k0 = find_k0(m_list[0], s_box_inv[c_list[0] ^ k2], k1)  # 注意这里传入的c（第二个参数）也要改
    crack_key = [k0, k1, k2]
    print(crack_key)  # [2, 7, 11]
    print(c_list == [cipherTWO(i, crack_key) for i in m_list])
    # 完全匹配所以正确，key = [2, 7, 11]


# 自动脚本

def find_keys(c0, c1, probable_out_diff):
    key_list = set()
    for k2 in range(16):
        w0 = s_box_inv[k2 ^ c0]
        w1 = s_box_inv[k2 ^ c1]
        if w0 ^ w1 in probable_out_diff:
            key_list.add(k2)
    return key_list


def find_k2(c_set, in_diff=0xf):
    probable_out_diff = list(dif_map(s_box, in_diff).keys())
    k2_set = find_keys(c_set[0][0], c_set[0][1], probable_out_diff)
    for i in range(1, len(c_set)):
        c0, c1 = c_set[i]
        k2_set &= find_keys(c0, c1, probable_out_diff)
    return k2_set


def verify(m_list, c_list, key):
    return c_list == [cipherTWO(i, key) for i in m_list]


def crack():
    from random import randint
    key = [randint(0, 15) for _ in range(3)]
    print(f"key(unknown) = {key}")
    m_list = [i for i in range(16)]
    c_list = [cipherTWO(i, key) for i in m_list]
    c_set = [(c_list[i], c_list[0xf - i]) for i in range(8)]
    k2_list = list(find_k2(c_set))
    for k2 in k2_list:
        c_set_for_k1 = [(s_box_inv[c_list[i] ^ k2], s_box_inv[c_list[0xf - i] ^ k2]) for i in range(8)]
        k1_list = find_k1(c_set_for_k1)
        for k1 in k1_list:
            k0 = find_k0(m_list[0], s_box_inv[c_list[0] ^ k2], k1)
            key = [k0, k1, k2]
            if verify(m_list, c_list, key):
                print(f"KEY FOUND!\nKEY = {key}")
                return


if __name__ == '__main__':
    crack()
