from filter_cascade import FilterCascade


MLBF_FILENAME = 'moz-crlite-mlbf'

counter = 0

a = []
b = []

wordfile = open('/usr/share/dict/words')

for word in wordfile.readlines():
    # let's say every third word should *not* be in the filter
    shouldAdd = (counter % 3 == 1)
    if shouldAdd:
        a.append(word)
    else:
        b.append(word)
    counter = counter + 1
wordfile.close()

cascade = FilterCascade(50000, 1.3, 0.77, 1)
cascade.initialize(a, b)
cascade.check(a, b)

print("This filter cascade uses %d layers and %d bits" % (
    cascade.layerCount(),
    cascade.bitCount())
)
print("Writing to file %s" % MLBF_FILENAME)

cascade.filter.tofile(open(MLBF_FILENAME, 'w'))
