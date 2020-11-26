#pragma once

#include <type_traits>
#include <utility>
#include <functional>

/**
 * This file contains specialized macros and templates that are hacky but useful.
 * WARNING: Reading this code may give you a headache.
 */

//
// TEMPLATES
//
namespace magic {

/**
 * A wrapper for std::tuple useful for storing a list of types that can be indexed into
 * with compile-time constants.
 *
 * Example Usage:
 *   template <size_t n>
 *   using my_types = type_list<int, long, char>::type<n>;
 *
 *   my_types<0> foo; // Same as `int foo`
 *   my_types<1> bar; // Same as `long bar`
 *   my_types<2> baz; // Same as `char baz`
 */
template <typename... Args>
struct type_list
{
   template <std::size_t N>
   using type = typename std::tuple_element<N, std::tuple<Args...>>::type;
};

/**
 * A way to inspect function signatures and retrieve parameter and return types.
 * Members:
 *   constexpr size_t arg_count: Number of arguments the function accepts
 *   RetT : Return type of function
 *   ArgsT : Argument types of function
 *
 * Example Usage:
 *   void my_fun(int);
 *
 *   using my_fun_traits = function_traits<decltype(&my_fun)>;
 *
 *   my_fun_traits::arg_count --> 1
 *   my_fun_traits::RetT      --> void
 *   my_fun_traits::ArgsT<0>  --> int
 *
 * A macro is used to specialize for std::functions, function pointers, and member function
 * pointers.
 */
template<typename T>
struct function_traits {
    static_assert(!std::is_same_v<T, T>, "function_traits not implemented for this type!");
};

#define SPECIALIZE_FUNCTION_TRAITS(S, ...) \
    template<__VA_ARGS__> \
    struct function_traits<S> { \
        static constexpr size_t arg_count = sizeof...(Args); \
        using RetT = R; \
        template <size_t i> \
        using ArgsT = typename type_list<Args...>::template type<i>; \
    };

SPECIALIZE_FUNCTION_TRAITS(std::function<R(Args...)>, typename R, typename... Args)
SPECIALIZE_FUNCTION_TRAITS(R(Args...), typename R, typename... Args)
SPECIALIZE_FUNCTION_TRAITS(R (C::*)(Args...), typename R, typename C, typename... Args)
SPECIALIZE_FUNCTION_TRAITS(R (C::*)(Args...) const, typename R, typename C, typename... Args)
#undef SPECIALIZE_FUNCTION_TRAITS

}; // namespace magic

//
// MACROS
//

/**
 * These magnificent macros allow us to execute each parameter passed to a macro.
 * This is useful for automating tasks that would otherwise require a lot of boilerplate and
 * code duplication.
 * For more information, see: https://stackoverflow.com/a/11994395.
 *
 * Example Usage:
 * To declare an int variable for each parameter passed to a macro, you could do something like this:
 *   #define DECLARE_INT(x) int x;
 *   #define DECLARE_INTS(...) FOR_EACH(DECLARE_INT, ##__VA_ARGS__)
 *
 *   DECLARE_INTS(foo, bar, baz)
 * This would result in the following output after the preprocessor is run:
 *   int foo;int bar;int baz;
 *
 * The main limitation is that the number of arguments that can be processed
 * is limited to the number of FE_ definitions below.
 */
#define FE_0(WHAT, ...)
#define FE_1(WHAT, X) WHAT(X)
#define FE_2(WHAT, X, ...) WHAT(X)FE_1(WHAT, __VA_ARGS__)
#define FE_3(WHAT, X, ...) WHAT(X)FE_2(WHAT, __VA_ARGS__)
#define FE_4(WHAT, X, ...) WHAT(X)FE_3(WHAT, __VA_ARGS__)
#define FE_5(WHAT, X, ...) WHAT(X)FE_4(WHAT, __VA_ARGS__)
#define FE_6(WHAT, X, ...) WHAT(X)FE_5(WHAT, __VA_ARGS__)

#define GET_MACRO(_0,_1,_2,_3,_4,_5,_6,NAME,...) NAME
#define FOR_EACH(action,...) \
  GET_MACRO(_0,##__VA_ARGS__,FE_6,FE_5,FE_4,FE_3,FE_2,FE_1,FE_0)(action,__VA_ARGS__)

/**
 * Declare a parallel array of enum values and types from a provided x-macro.
 * This can be used in constexpr functions that look up a given type from an enum value
 * or vice versa.
 *
 * Example Usage:
 * First, you need an x-macro that declares pairs of enum values and types, e.g.
 *   #define ENUMERATE_RECIPES(x) \
 *       x(CAKE, chef:bake) \
 *       x(PASTA, chef:cook) \
 *       x(BURGER, chef:grill)
 * You also need an enum class that defines all the first values (i.e. Dishes),
 * and a class that contains the methods listed in the second values.
 *
 * Finally, you need to declare accessors for each field of the x-macro, like such
 * (note the commas at the end, required for list declarations):
 *   #define ACCESS_ENUM(first, second) first,
 *   #define ACCESS_TYPE(first, second) decltype(&second),
 *
 * Now you can use the macro to declare the type lookup tables.
 *   GEN_ENUM_TO_TYPE_LOOKUP(ENUMERATE_RECIPES, recipe_lut, ACCESS_ENUM, ACCESS_TYPE, Dishes)
 * where Dishes is the type of the enum class that contains all the first values in the x-macro.
 *
 * Now you can use the generated template `name ## _look_up_type<EnumT value>` to retrieve the
 * type for a given enum value.
 *
 * In the case of the examples above:
 *   recipe_lut_look_up_type<Dishes::CAKE>  --> decltype(&chef:bake)
 *   recipe_lut_look_up_type<Dishes::PASTA>  --> decltype(&chef:cook)
 *   recipe_lut_look_up_type<Dishes::BURGER>  --> decltype(&chef:grill)
 *
 * This is probably the most magic thing in this file.
 */
#define GEN_ENUM_TO_TYPE_LOOKUP(xm, name, enum_accessor, type_accessor, EnumT) \
constexpr EnumT name ## _enums[] { \
    xm(enum_accessor) \
}; \
template <size_t n> \
using name ## _types = \
    magic::type_list< \
                     xm(type_accessor) \
                               void>::type<n>; \
template <EnumT e, size_t n = 0> \
constexpr size_t name ## _lookup_type_index() { \
    if constexpr (name ## _enums[n] == e || ARRAY_SIZE(name ## _enums) - 1 == n) \
        return n; \
    else \
        return name ## _lookup_type_index<e, n + 1>(); \
} \
template <EnumT e> \
using name ## _look_up_type = name ## _types<name ## _lookup_type_index<e>()>;

