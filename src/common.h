/*
 * common.h - Provide global definitions
 *
 * You should have received a copy of the GNU General Public License
 * see <http://www.gnu.org/licenses/>.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#ifndef __weak_ptr
#define __weak_ptr
#endif

/* ASSERT() is for debug checks, VERIFY() for run-time sanity checks.
* DEBUG_VERIFIES is for expensive debug verifies that we only want to
* enable in debug builds but still want type-checked by the compiler
* in release builds.
*/
#if defined(NDEBUG)
# define ASSERT(exp)
# define VERIFY(exp)   do { if (!(exp)) { abort(); } } while (0)
# define DEBUG_VERIFIES (0)
#else
#include <assert.h>
# define ASSERT(exp)  assert(exp)
# define VERIFY(exp)   assert(exp)
# define DEBUG_VERIFIES (1)
#endif

#define UNREACHABLE() VERIFY(!"Unreachable code reached.")

#if !defined(CONTAINER_OF)
#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))
#endif // !defined(CONTAINER_OF)

#endif // __COMMON_H__
