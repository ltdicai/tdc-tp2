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
    print tau

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
    print o
    if len(o) == 1:
        return [itemgetter(*o)(sortindex)]
    elif len(o) > 1:
        return itemgetter(*o)(sortindex)
    else:
        return []


res = [10,10,10,1, 10,10,11]
lista = sorted(res)
lista.reverse()
print lista
print thompson_tau_test(res)
