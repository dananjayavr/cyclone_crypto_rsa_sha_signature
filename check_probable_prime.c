/*
 *  Multi-precision integer library
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  The following sources were referenced in the design of this Multi-precision
 *  Integer library:
 *
 *  [1] Handbook of Applied Cryptography - 1997
 *      Menezes, van Oorschot and Vanstone
 *
 *  [2] Multi-Precision Math
 *      Tom St Denis
 *      https://github.com/libtom/libtommath/blob/develop/tommath.pdf
 *
 *  [3] GNU Multi-Precision Arithmetic Library
 *      https://gmplib.org/manual/index.html
 *
 */

//!!!MODIFIED FILE!!!
#include "core/crypto.h"
#include "mpi/mpi.h"
#include "rng/yarrow.h"

extern YarrowContext yarrowContext;

#define MBEDTLS_MPI_CHK(f) if((ret = f) != 0) goto cleanup
#define mbedtls_mpi Mpi
#define mbedtls_mpi_sint int_t
#define mbedtls_mpi_uint uint_t
#define mbedtls_mpi_init mpiInit
#define mbedtls_mpi_free mpiFree
#define mbedtls_mpi_sub_int mpiSubInt
#define mbedtls_mpi_copy mpiCopy
#define mbedtls_mpi_shift_r mpiShiftRight
#define mbedtls_mpi_shift_l mpiShiftLeft
#define mbedtls_mpi_bitlen mpiGetBitLength
#define mbedtls_mpi_cmp_mpi mpiComp
#define mbedtls_mpi_cmp_int mpiCompInt
#define mbedtls_mpi_add_int mpiAddInt
#define mbedtls_mpi_mul_mpi mpiMul
#define mbedtls_mpi_mod_mpi mpiMod
#define mbedtls_mpi_inv_mod mpiInvMod
#define mbedtls_mpi_lset mpiSetValue
#define mbedtls_mpi_set_bit mpiSetBitValue
#define mbedtls_mpi_exp_mod mpiExpMod
#define mbedtls_mpi_sub_abs mpiSubAbs
#define mbedtls_mpi_fill_random(xx, nn, algo, ctx) mpiRand(xx, (nn) * 8, algo, ctx)

#define ciL    (sizeof(mbedtls_mpi_uint))         /* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )

#define MBEDTLS_MPI_MAX_BITS 4096
#define MBEDTLS_ERR_MPI_NOT_ACCEPTABLE (2)
#define MBEDTLS_ERR_MPI_BAD_INPUT_DATA (3)
#define MBEDTLS_ERR_RSA_BAD_INPUT_DATA (4)
#define MBEDTLS_ERR_RSA_KEY_GEN_FAILED (5)
#define MBEDTLS_ERR_MPI_DIVISION_BY_ZERO (6)
#define MBEDTLS_ERR_MPI_NEGATIVE_VALUE (7)

static const int small_prime[] =
{
        3,    5,    7,   11,   13,   17,   19,   23,
       29,   31,   37,   41,   43,   47,   53,   59,
       61,   67,   71,   73,   79,   83,   89,   97,
      101,  103,  107,  109,  113,  127,  131,  137,
      139,  149,  151,  157,  163,  167,  173,  179,
      181,  191,  193,  197,  199,  211,  223,  227,
      229,  233,  239,  241,  251,  257,  263,  269,
      271,  277,  281,  283,  293,  307,  311,  313,
      317,  331,  337,  347,  349,  353,  359,  367,
      373,  379,  383,  389,  397,  401,  409,  419,
      421,  431,  433,  439,  443,  449,  457,  461,
      463,  467,  479,  487,  491,  499,  503,  509,
      521,  523,  541,  547,  557,  563,  569,  571,
      577,  587,  593,  599,  601,  607,  613,  617,
      619,  631,  641,  643,  647,  653,  659,  661,
      673,  677,  683,  691,  701,  709,  719,  727,
      733,  739,  743,  751,  757,  761,  769,  773,
      787,  797,  809,  811,  821,  823,  827,  829,
      839,  853,  857,  859,  863,  877,  881,  883,
      887,  907,  911,  919,  929,  937,  941,  947,
      953,  967,  971,  977,  983,  991,  997, -103
};


/*
 * Return the number of less significant zero-bits
 */
size_t mbedtls_mpi_lsb( const mbedtls_mpi *X )
{
    size_t i, j, count = 0;

    for( i = 0; i < X->size; i++ )
        for( j = 0; j < 32; j++, count++ )
            if( ( ( X->data[i] >> j ) & 1 ) != 0 )
                return( count );

    return( 0 );
}


/*
 * Modulo: r = A mod b
 */
int mbedtls_mpi_mod_int( mbedtls_mpi_uint *r, const mbedtls_mpi *A, mbedtls_mpi_sint b )
{
    size_t i;
    mbedtls_mpi_uint x, y, z;

    if( b == 0 )
        return( MBEDTLS_ERR_MPI_DIVISION_BY_ZERO );

    if( b < 0 )
        return( MBEDTLS_ERR_MPI_NEGATIVE_VALUE );

    /*
     * handle trivial cases
     */
    if( b == 1 )
    {
        *r = 0;
        return( 0 );
    }

    if( b == 2 )
    {
        *r = A->data[0] & 1;
        return( 0 );
    }

    /*
     * general case
     */
    for( i = A->size, y = 0; i > 0; i-- )
    {
        x  = A->data[i - 1];
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;

        x <<= biH;
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;
    }

    /*
     * If A is negative, then the current y represents a negative value.
     * Flipping it to the positive side.
     */
    if( A->sign < 0 && y != 0 )
        y = b - y;

    *r = y;

    return( 0 );
}


/*
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
int mbedtls_mpi_gcd( mbedtls_mpi *G, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret;
    size_t lz, lzt;
    mbedtls_mpi TG, TA, TB;

    mbedtls_mpi_init( &TG ); mbedtls_mpi_init( &TA ); mbedtls_mpi_init( &TB );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &TA, A ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &TB, B ) );

    lz = mbedtls_mpi_lsb( &TA );
    lzt = mbedtls_mpi_lsb( &TB );

    if( lzt < lz )
        lz = lzt;

    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &TA, lz ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &TB, lz ) );

    TA.sign = TB.sign = 1;

    while( mbedtls_mpi_cmp_int( &TA, 0 ) != 0 )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &TA, mbedtls_mpi_lsb( &TA ) ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &TB, mbedtls_mpi_lsb( &TB ) ) );

        if( mbedtls_mpi_cmp_mpi( &TA, &TB ) >= 0 )
        {
            MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( &TA, &TA, &TB ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &TA, 1 ) );
        }
        else
        {
            MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( &TB, &TB, &TA ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &TB, 1 ) );
        }
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &TB, lz ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( G, &TB ) );

cleanup:

    mbedtls_mpi_free( &TG );
    mbedtls_mpi_free( &TA );
    mbedtls_mpi_free( &TB );

    return( ret );
}


/*
 * Small divisors test (X must be positive)
 *
 * Return values:
 * 0: no small factor (possible prime, more tests needed)
 * 1: certain prime
 * MBEDTLS_ERR_MPI_NOT_ACCEPTABLE: certain non-prime
 * other negative: error
 */
static int mpi_check_small_factors( const mbedtls_mpi *X )
{
    int ret = 0;
    size_t i;
    mbedtls_mpi_uint r;

    if( ( X->data[0] & 1 ) == 0 )
        return( MBEDTLS_ERR_MPI_NOT_ACCEPTABLE );

    for( i = 0; small_prime[i] > 0; i++ )
    {
        if( mbedtls_mpi_cmp_int( X, small_prime[i] ) <= 0 )
            return( 1 );

        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_int( &r, X, small_prime[i] ) );

        if( r == 0 )
            return( MBEDTLS_ERR_MPI_NOT_ACCEPTABLE );
    }

cleanup:
    return( ret );
}

/*
 * Miller-Rabin pseudo-primality test  (HAC 4.24)
 */
static int mpi_miller_rabin( const mbedtls_mpi *X,
                             const PrngAlgo *prngAlgo, void *prngContext)
{
    int ret, count;
    size_t i, j, k, n, s;
    mbedtls_mpi W, R, T, A; //, RR;

    mbedtls_mpi_init( &W );
    mbedtls_mpi_init( &R );
    mbedtls_mpi_init( &T );
    mbedtls_mpi_init( &A );
    //mbedtls_mpi_init( &RR );

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &W, X, 1 ) );
    s = mbedtls_mpi_lsb( &W );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R, &W ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &R, s ) );

    i = mbedtls_mpi_bitlen( X );
    /*
     * HAC, table 4.4
     */
    n = ( ( i >= 1300 ) ?  2 : ( i >=  850 ) ?  3 :
          ( i >=  650 ) ?  4 : ( i >=  350 ) ?  8 :
          ( i >=  250 ) ? 12 : ( i >=  150 ) ? 18 : 27 );

    for( i = 0; i < n; i++ )
    {
        /*
         * pick a random A, 1 < A < |X| - 1
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &A, X->size * ciL, prngAlgo, prngContext ) );

        if( mbedtls_mpi_cmp_mpi( &A, &W ) >= 0 )
        {
            j = mbedtls_mpi_bitlen( &A ) - mbedtls_mpi_bitlen( &W );
            MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &A, j + 1 ) );
        }
        A.data[0] |= 3;

        count = 0;
        do {
            MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &A, X->size * ciL, prngAlgo, prngContext ) );

            j = mbedtls_mpi_bitlen( &A );
            k = mbedtls_mpi_bitlen( &W );
            if (j > k) {
                MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &A, j - k ) );
            }

            if (count++ > 30) {
                return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            }

        } while ( mbedtls_mpi_cmp_mpi( &A, &W ) >= 0 ||
                  mbedtls_mpi_cmp_int( &A, 1 )  <= 0    );

        /*
         * A = A^R mod |X|
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &A, &A, &R, X /*, &RR*/ ) );

        if( mbedtls_mpi_cmp_mpi( &A, &W ) == 0 ||
            mbedtls_mpi_cmp_int( &A,  1 ) == 0 )
            continue;

        j = 1;
        while( j < s && mbedtls_mpi_cmp_mpi( &A, &W ) != 0 )
        {
            /*
             * A = A * A mod |X|
             */
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &A, &A ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &A, &T, X  ) );

            if( mbedtls_mpi_cmp_int( &A, 1 ) == 0 )
                break;

            j++;
        }

        /*
         * not prime if A != |X| - 1 or A == 1
         */
        if( mbedtls_mpi_cmp_mpi( &A, &W ) != 0 ||
            mbedtls_mpi_cmp_int( &A,  1 ) == 0 )
        {
            ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            break;
        }
    }

cleanup:
    mbedtls_mpi_free( &W );
    mbedtls_mpi_free( &R );
    mbedtls_mpi_free( &T );
    mbedtls_mpi_free( &A );
    //mbedtls_mpi_free( &RR );

    return( ret );
}


/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
int mbedtls_mpi_is_prime( const mbedtls_mpi *X,
                  const PrngAlgo *prngAlgo, void *prngContext )
{
    int ret;
    mbedtls_mpi XX;

    XX.sign = 1;
    XX.size = X->size;
    XX.data = X->data;

    if( mbedtls_mpi_cmp_int( &XX, 0 ) == 0 ||
        mbedtls_mpi_cmp_int( &XX, 1 ) == 0 )
        return( MBEDTLS_ERR_MPI_NOT_ACCEPTABLE );

    if( mbedtls_mpi_cmp_int( &XX, 2 ) == 0 )
        return( 0 );

    if( ( ret = mpi_check_small_factors( &XX ) ) != 0 )
    {
        if( ret == 1 )
            return( 0 );

        return( ret );
    }

    return( mpi_miller_rabin( &XX, prngAlgo, prngContext ) );
}


error_t mpiCheckProbablePrime(const Mpi *a)
{
   int err;
   
   err = mbedtls_mpi_is_prime(a, YARROW_PRNG_ALGO, &yarrowContext);
   
   if(err == 0)
      return NO_ERROR;
   else if(err == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE)
      return ERROR_INVALID_VALUE;
   else
      return ERROR_FAILURE;
}
