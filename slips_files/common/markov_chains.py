import math
import sys


class Matrix(dict):
    """The basic matrix object"""

    def __init__(self, *args, **kw):
        super(Matrix, self).__init__(*args, **kw)
        self.itemlist = super(Matrix, self).keys()

    def set_init_vector(self, init_vector):
        self.init_vector = init_vector

    def get_init_vector(self):
        return self.init_vector

    def walk_probability(self, states):
        """
        Compute the probability of generating these states using ourselves.
        The returned value must be log.
        The main feature of this markov function is that is not trying to
        recognize each "state", it just uses each position of the vector
        given as new state. This allow us to have more comple states
        to work.
        """
        try:
            cum_prob = 0
            index = 0
            while index < len(states) - 1 and len(states) > 1:
                statestuple = (states[index], states[index + 1])

                try:
                    prob12 = math.log(float(self[statestuple]))
                except KeyError:
                    cum_prob = float('-inf')
                    break

                cum_prob += prob12
                index += 1

            return cum_prob
        except Exception as err:
            print(type(err))
            print(err.args)
            print(err)
            sys.exit(-1)


def maximum_likelihood_probabilities(states, order=1):
    """Our own second order Markov Chain implementation"""
    initial_matrix = {}
    total_transitions = 0


    if order == 1:

        index = 0
        initial_vector = {}
        amount_of_states = len(states)
        while index < amount_of_states:
            state1 = states[index]
            try:
                state2 = states[index + 1]
            except IndexError:

                break
            try:
                initial_matrix[state1]
            except KeyError:

                initial_matrix[state1] = {}
                initial_vector[state1] = 0
            try:
                value = initial_matrix[state1][state2]
                initial_matrix[state1][state2] = value + 1
            except KeyError:

                initial_matrix[state1][state2] = 1
            initial_vector[state1] += 1
            total_transitions += 1

            index += 1

        matrix = Matrix()
        init_vector = {}
        for state1 in initial_matrix:

            init_vector[state1] = initial_vector[state1] / float(
                total_transitions
            )
            for state2 in initial_matrix[state1]:
                value = initial_matrix[state1][state2]
                initial_matrix[state1][state2] = value / float(
                    initial_vector[state1]
                )

                matrix[(state1, state2)] = initial_matrix[state1][state2]
        matrix.set_init_vector(init_vector)

    return (init_vector, matrix)
