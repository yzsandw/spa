// /**
//  * \file server/spad_utests.c
//  *
//  * \brief 服务器的CUnit测试。
//  */

// #include "CUnit/Basic.h"

// #include "spad_common.h"
// #include "access.h"

// /**
//  * 注册ZTN文件中的测试套件
//  *
//  * 模块应根据所使用的模块获取相应的函数，这些函数都遵循相同的命名约定。
//  */
// static void register_test_suites(void)
// {
//     register_ts_access();
// }

// /* 设置和运行测试的主函数。
//  * 在成功运行时返回CUE_SUCCESS，失败时返回CUnit的其他错误代码。 
//  */
// int main()
// {
//     /* 初始化CUnit测试注册表。 */
//     if (CUE_SUCCESS != CU_initialize_registry())
//         return CU_get_error();

//     /* 从ZTN文件注册测试套件*/
//     register_test_suites();

//     /* 使用CUnit基本接口运行所有测试 */
//     CU_basic_set_mode(CU_BRM_VERBOSE);
//     CU_basic_run_tests();
//     CU_cleanup_registry();
//     return CU_get_error();
// }
