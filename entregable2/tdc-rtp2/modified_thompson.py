import math
import statistics
from operator import itemgetter
from scipy import stats

def detect_outlier(data,alpha,outlier_index,start_index):
    original_data = data
    data = [i for j, i in enumerate(data) if j not in outlier_index]
    n = len(data)
    if n < 3 :
        return []

    sd = statistics.stdev(data)
    mean = statistics.mean(data)
    delta_min = abs(data[0] - mean)
    delta_max = abs(data[-1] - mean)

    if delta_max > delta_min:
        index = n - 1
        delta = delta_max
    else:
        index = 0
        delta = delta_min

    t_a2 = stats.t.ppf(1-(alpha/2.), n-2)
    tau = (t_a2 * (n-1) ) /(math.sqrt(n) * math.sqrt(n-2 + t_a2**2))
    tauS = tau * sd

    if delta > tauS:
        if index == 0 :
            outlier_index.append(start_index)
            start_index = start_index + 1
        else:
            outlier_index.append(start_index + index)
        detect_outlier(original_data,alpha,outlier_index,start_index)

    return outlier_index

def thompson_tau_test(data, alpha = 0.05):
    n = len(data)
    sortindex = sorted(range(n), key=lambda k: data[k])
    sorted_data = sorted(data)
    o = detect_outlier(sorted_data,alpha,[],0)
    if len(o) == 1:
        return [itemgetter(*o)(sortindex)]
    elif len(o) > 1:
        return itemgetter(*o)(sortindex)
    else:
        return []

# res = [0.055666983127593994, 0.05544447898864746, 0.11905926465988159, 0.2634722590446472, 0.275656521320343, 0.28383326530456543, 0.26414918899536133, 0.311149537563324, 0.32288581132888794, 0.4001304507255554, 0.3802558183670044, 0.4464760422706604, 0.3491893410682678]
# res2 = []
# res2.append(round(res[0], 4))
# for i in xrange(1, len(res)):
#     res2.append(abs(round(res[i] - res[i-1], 4)))
# print res
# print res2
# lista = sorted(res2)
# #lista.reverse()
# print lista
# print thompson_tau_test(res2)
