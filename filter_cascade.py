from pybloom import BloomFilter


class FilterCascade:
    def __init__(self, capacity, oversize_factor, error_rate, depth):
        self.capacity = capacity
        self.error_rate = error_rate
        self.filter = BloomFilter(
            capacity=int(self.capacity * oversize_factor),
            error_rate=self.error_rate
        )
        self.exclusions = []
        self.childLayer = None
        self.depth = depth
        self.oversize_factor = oversize_factor

    def initialize(self, entries, exclusions):
        # loop over the elements that should be there. Add them to the filter.
        for elem in entries:
            self.filter.add(elem)

        # loop over the elements that should *not* be there. Create a new layer
        # that *includes* the false positives and *excludes* the true positives
        falsePositives = []

        for elem in exclusions:
            if elem in self.filter:
                falsePositives.append(elem)

        if len(falsePositives) > 0:
            self.childLayer = FilterCascade(
                                int(len(falsePositives)),
                                self.oversize_factor,
                                self.error_rate,
                                self.depth + 1
                              )
            # salt entries in some variable but deterministic way
            self.childLayer.initialize(
                [pos + "a" * self.depth for pos in falsePositives],
                [pos + "a" * self.depth for pos in entries]
            )

    def __contains__(self, elem):
        if elem in self.filter:
            if self.childLayer is None:
                return True
            else:
                return not elem + "a" * self.depth in self.childLayer

    def check(self, entries, exclusions):
        for entry in entries:
            if entry not in self:
                raise ValueError("oops! false negative!")
        for entry in exclusions:
            if entry in self:
                raise ValueError("oops! false positive!")

    def bitCount(self):
        if self.childLayer is None:
            return len(self.filter.bitarray)
        return len(self.filter.bitarray) + self.childLayer.bitCount()

    def layerCount(self):
        if self.childLayer is None:
            return 1
        else:
            return self.childLayer.layerCount() + 1
