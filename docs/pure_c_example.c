#include "../mrpa/context_c.h"
#include "../csp/checks/bool_results.hpp"
#include "../c_bridge/pod_structs.hpp"
#include "../c_bridge/c_bridge.hpp"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int main(){
      // JSON tree build from array
      TreeContext* ctx=CreateContext();
      const JsonString* jstr=AddFilesJsonList(ctx,"[\"../test_files/mrpa/sensitive/Входящий УПД №0089714952 от 19.05.25.zip\"]");
      const JsonString* tree_json=BuildTree(ctx);
      printf("Tree:\n %s",GetString(tree_json));
      FreeJsonString(tree_json);
      FreeJsonString(jstr);
      DestroyContext(ctx); 
      
      // simple attached signature check
      struct CPodParam param={0};
      param.sig_file_path="../test_files/mrpa/sigs/attached993.sig";
      param.sig_file_path_size=strlen(param.sig_file_path);
      struct CPodResult* res=CheckSimpleAttached(param);
      if (res->bres.check_summary){
            printf("Signature is OK");
      }else{
           printf("Signature is BAD"); 
      }
      CFreeResult(res);
      return 0;
}

// clang test_from_c.c  -L${PROJECT_DIR}/build/mrpa/  -lmrpa -L${PROJECT_DIR}/build/c_bridge/ -lcsp_c_bridge -I${PROJECT_DIR}/csp/checks/ -Wall -Wextra
// LD_PRELOAD="${PROJECT_DIR}/build/c_bridge/libcsp_c_bridge.so.0.1:${PROJECT_DIR}/build/mrpa/libmrpa.so" ./a.out
