// Generic helper definitions for shared library support
#if defined _WIN32 || defined __CYGWIN__
  #define KMSENGINE_HELPER_DLL_IMPORT __declspec(dllimport)
  #define KMSENGINE_HELPER_DLL_EXPORT __declspec(dllexport)
  #define KMSENGINE_HELPER_DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define KMSENGINE_HELPER_DLL_IMPORT __attribute__ ((visibility ("default")))
    #define KMSENGINE_HELPER_DLL_EXPORT __attribute__ ((visibility ("default")))
    #define KMSENGINE_HELPER_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define KMSENGINE_HELPER_DLL_IMPORT
    #define KMSENGINE_HELPER_DLL_EXPORT
    #define KMSENGINE_HELPER_DLL_LOCAL
  #endif
#endif

// Now we use the generic helper definitions above to define KMSENGINE_API and KMSENGINE_LOCAL.
// KMSENGINE_API is used for the public API symbols. It either DLL imports or DLL exports (or does nothing for static build)
// KMSENGINE_LOCAL is used for non-api symbols.

#ifdef KMSENGINE_DLL // defined if FOX is compiled as a DLL
  #ifdef KMSENGINE_DLL_EXPORTS // defined if we are building the FOX DLL (instead of using it)
    #define KMSENGINE_API KMSENGINE_HELPER_DLL_EXPORT
  #else
    #define KMSENGINE_API KMSENGINE_HELPER_DLL_IMPORT
  #endif // KMSENGINE_DLL_EXPORTS
  #define KMSENGINE_LOCAL KMSENGINE_HELPER_DLL_LOCAL
#else // KMSENGINE_DLL is not defined: this means FOX is a static lib.
  #define KMSENGINE_API
  #define KMSENGINE_LOCAL
#endif // KMSENGINE_DLL
