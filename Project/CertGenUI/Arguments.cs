using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CertGenUI
{
    /// <summary>
    /// Provides methods to validate and transform method arguments.
    /// </summary>
    public static class Arguments
    {
        #region Parameters check

        #region Null, empty or default

        /// <summary>
        /// Throws an exception if the specified value is null.
        /// </summary>
        /// <param name="value"></param>
        /// <exception cref="ArgumentNullException"/>
        public static void NotNull<T>(T value, string paramName) where T : class
        {
            if (value == null)
            {
                throw new ArgumentNullException(paramName);
            }
        }

        /// <summary>
        /// Throws an exception if the specified value is <see cref="Guid.Empty"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        public static void NotNull<T>(Nullable<T> value, string paramName) where T : struct
        {
            if (false == value.HasValue)
            {
                throw new ArgumentNullException(paramName);
            }
        }

        /// <summary>
        /// Throws an exception if the specified value is <see cref="Guid.Empty"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        public static void NotEmpty(Guid value, string paramName)
        {
            if (value == Guid.Empty)
            {
                throw new ArgumentNullException(paramName);
            }
        }

        /// <summary>
        /// Throws an exception if the specified value is <see cref="DateTime.MinValue"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        public static void NotDefault(DateTime value, string paramName)
        {
            if (value == DateTime.MinValue)
            {
                throw new ArgumentNullException(paramName);
            }
        }

        /// <summary>
        /// Throws an exception if the specified value is <see cref="TimeSpan.Zero"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        public static void NotDefault(TimeSpan value, string paramName)
        {
            if (value == TimeSpan.Zero)
            {
                throw new ArgumentNullException(paramName);
            }
        }

        /// <summary>
        /// Throws an exception if the specified value is the default value for the type.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        public static void NotDefault<T>(T value, string paramName) where T : struct
        {
            if (EqualityComparer<T>.Default.Equals(value, default(T)))
            {
                throw new ArgumentNullException(paramName);
            }
        }

        #region String

        /// <summary>
        /// Throws an exception if the specified value is <c>null</c> or empty string.
        /// </summary>
        public static void NotNullOrEmpty(string value, string paramName)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentNullException(paramName);
            }
        }

        /// <summary>
        /// Throws an exception if the specified value is <c>null</c>, empty string or consists only of white-space characters.
        /// </summary>
        public static void NotNullOrWhiteSpace(string value, string paramName)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentNullException(paramName);
            }
        }

        #endregion

        #endregion

        #region Comparison

        #region Struct

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than
        /// <paramref name="from"/> or greater than <see cref="to"/>.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="from"></param>
        /// <param name="to"></param>
        /// <param name="parameter"></param>
        public static void InRange<T>(T from, T to, T value, string parameter)
        {
            if (Comparer<T>.Default.Compare(value, from) < 0 || Comparer<T>.Default.Compare(value, to) > 0)
            {
                throw new ArgumentOutOfRangeException(parameter, value, string.Format("Must be between {0} and {1}.", from, to));
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to
        /// the default value of type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void Positive<T>(T value, string parameterName) where T : struct, IComparable<T>
        {
            if (Comparer<T>.Default.Compare(value, default(T)) <= 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a positive value.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to
        /// the default value of type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void Positive<T>(T? value, string parameterName) where T : struct, IComparable<T>
        {
            if (value != null)
            {
                Positive<T>(value.Value, parameterName);
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than
        /// the default value of type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void PositiveOrDefault<T>(T value, string parameterName) where T : struct, IComparable<T>
        {
            if (Comparer<T>.Default.Compare(value, default(T)) < 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a non-negative value.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than
        /// the default value of type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void PositiveOrDefault<T>(T? value, string parameterName) where T : struct, IComparable<T>
        {
            if (value != null)
            {
                PositiveOrDefault<T>(value.Value, parameterName);
            }
        }

        #endregion

        #region Int32

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than
        /// <paramref name="from"/> or greater than <see cref="to"/>.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="from"></param>
        /// <param name="to"></param>
        /// <param name="parameter"></param>
        public static void InRange(int from, int to, int value, string parameter)
        {
            if (value < from || value > to)
            {
                throw new ArgumentOutOfRangeException(parameter, value, string.Format("Must be between {0} and {1}.", from, to));
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void Positive(int value, string parameterName)
        {
            if (value <= 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a positive number.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void Positive(int? value, string parameterName)
        {
            if (value != null)
            {
                Positive(value.Value, parameterName);
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void PositiveOrDefault(int value, string parameterName)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a non-negative number.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void PositiveOrDefault(int? value, string parameterName)
        {
            if (value != null)
            {
                PositiveOrDefault(value.Value, parameterName);
            }
        }

        #endregion

        #region Int64

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than
        /// <paramref name="from"/> or greater than <see cref="to"/>.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="from"></param>
        /// <param name="to"></param>
        /// <param name="parameter"></param>
        public static void InRange(long from, long to, long value, string parameter)
        {
            if (value < from || value > to)
            {
                throw new ArgumentOutOfRangeException(parameter, value, string.Format("Must be between {0} and {1}.", from, to));
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void Positive(long value, string parameterName)
        {
            if (value <= 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a positive number.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void Positive(long? value, string parameterName)
        {
            if (value != null)
            {
                Positive(value.Value, parameterName);
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void PositiveOrDefault(long value, string parameterName)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a non-negative number.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void PositiveOrDefault(long? value, string parameterName)
        {
            if (value != null)
            {
                PositiveOrDefault(value.Value, parameterName);
            }
        }

        #endregion

        #region Double

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than
        /// <paramref name="from"/> or greater than <see cref="to"/>.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="from"></param>
        /// <param name="to"></param>
        /// <param name="parameter"></param>
        public static void InRange(double from, double to, double value, string parameter)
        {
            if (value < from || value > to)
            {
                throw new ArgumentOutOfRangeException(parameter, value, string.Format("Must be between {0} and {1}.", from, to));
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void Positive(double value, string parameterName)
        {
            if (value <= 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a positive number.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void Positive(double? value, string parameterName)
        {
            if (value != null)
            {
                Positive(value.Value, parameterName);
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void PositiveOrDefault(double value, string parameterName)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a non-negative number.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void PositiveOrDefault(double? value, string parameterName)
        {
            if (value != null)
            {
                PositiveOrDefault(value.Value, parameterName);
            }
        }

        #endregion

        #region Decimal

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than
        /// <paramref name="from"/> or greater than <see cref="to"/>.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="from"></param>
        /// <param name="to"></param>
        /// <param name="parameter"></param>
        public static void InRange(decimal from, decimal to, decimal value, string parameter)
        {
            if (value < from || value > to)
            {
                throw new ArgumentOutOfRangeException(parameter, value, string.Format("Must be between {0} and {1}.", from, to));
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void Positive(decimal value, string parameterName)
        {
            if (value <= 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a positive number.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than or equal to zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void Positive(decimal? value, string parameterName)
        {
            if (value != null)
            {
                Positive(value.Value, parameterName);
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static void PositiveOrDefault(decimal value, string parameterName)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException("value", value, "Must be a non-negative number.");
            }
        }

        /// <summary>
        /// Throws an <see cref="ArgumentOutOfRangeException"/> if <paramref name="value"/> is less than zero.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value">The value.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <remarks>
        /// If the value is <c>null</c> then no exception is thrown.
        /// </remarks>
        public static void PositiveOrDefault(decimal? value, string parameterName)
        {
            if (value != null)
            {
                PositiveOrDefault(value.Value, parameterName);
            }
        }

        #endregion

        #endregion

        #endregion

        #region Transformation

        /// <summary>
        /// Removes the white space in the beginning and in the end of the specified <see cref="String"/>.
        /// If the resulting string is an empty string replaces the value with null.
        /// </summary>
        /// <param name="value">The string to trim.</param>
        /// <remarks>
        /// If <paramref name="value"/> is <c>null</c> then it remains unchanged.
        /// </remarks>
        public static void TrimToNull(ref string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                value = null;
            }
            else
            {
                value = value.Trim();
            }
        }

        /// <summary>
        /// Removes the white space in the beginning and in the end of the specified value.
        /// If the resulting string is an empty string returns null.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns><paramref name="value"/> without leading or trailing space or <c>null</c> if <paramref name="value"/>
        /// is null or contains only white space characters.</returns>
        public static string TrimToNull(this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }
            else
            {
                return value.Trim();
            }
        }

        /// <summary>
        /// Returns <c>null</c> if the specified value is the default value for the type <typeparamref name="T"/>;
        /// otherwise, returns <paramref name="value"/> unchanged.
        /// </summary>
        /// <typeparam name="T">The type.</typeparam>
        /// <param name="value">The value.</param>
        /// <returns>The result.</returns>
        public static T? NullIfDefault<T>(this T value) where T : struct
        {
            if (EqualityComparer<T>.Default.Equals(value, default(T)))
            {
                return null;
            }
            else
            {
                return value;
            }
        }

        /// <summary>
        /// Returns <c>null</c> if the <paramref name="value"/> equals <paramref name="valueToCompare"/>;
        /// otherwise, returns <paramref name="value"/> unchanged.
        /// </summary>
        /// <typeparam name="T">The type.</typeparam>
        /// <param name="value">The value.</param>
        /// <param name="valueToCompare">The value to compare with.</param>
        /// <returns>
        /// The result.
        /// </returns>
        public static T? NullIf<T>(this T value, T valueToCompare) where T : struct
        {
            if (EqualityComparer<T>.Default.Equals(value, valueToCompare))
            {
                return null;
            }
            else
            {
                return value;
            }
        }

        #endregion
    }
}
