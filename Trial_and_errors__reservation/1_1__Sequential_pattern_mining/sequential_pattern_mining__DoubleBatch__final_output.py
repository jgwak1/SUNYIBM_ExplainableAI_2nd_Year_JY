import json
from pathlib import Path
import sys
import datetime
import gc

# https://github.com/fidelity/seq2pat/blob/master/notebooks/sequential_pattern_mining.ipynb
# https://fidelity.github.io/seq2pat/index.html

import numpy as np
import psutil
import pickle
import os


from sequential.utils import *
import collections


if __name__ == "__main__":

   all_batch_processing_start_time = datetime.datetime.now()

   #######################################################################################################################
   # Now read in all super-batch SPM results from pickle file and
   # compute the final output , 
   # maybe use their aggregation results

   #----------------------------------------------------------------------------------------------------------------------
   # This is what matters, which I will compute based on the final output (aggregation of super-batch outputs)
   
   number_of_total_indicies = 96
   min_ratio = 0.3
   min_row_count = int(number_of_total_indicies * min_ratio) 
   
   # ---------------------------------------------------------------------------------------------------------------------
   counter = collections.Counter()


   super_batch_spm_result_pickles_dirpath =\
   "/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_1__Sequential_pattern_mining/super_batch_spm_result_pickles_dir__2023-10-29 22:15:54"

   super_batch_output_pickle_files = os.listdir(super_batch_spm_result_pickles_dirpath)

   for super_batch_output_pickle_file in super_batch_output_pickle_files:

      print(f"start processing {super_batch_output_pickle_file}", flush=True)

      super_batch_processing_start_time = datetime.datetime.now()

      super_batch_output_pickle_fpath = os.path.join( super_batch_spm_result_pickles_dirpath, 
                                                      super_batch_output_pickle_file )

      super_batch_output = pickle.load( open(super_batch_output_pickle_fpath, "rb") )

      counter.update( list_to_counter(super_batch_output) )


      # ----------
      memory_percent = psutil.virtual_memory().percent
      print(f"(Before del & gc.collect) -- Memory usage: {memory_percent}%", flush = True)          

      del super_batch_output
      gc.collect()
   
      memory_percent = psutil.virtual_memory().percent
      print(f"(After del & gc.collect) -- Memory usage: {memory_percent}%", flush = True)          

      # ----------
      super_batch_processing_end_time = datetime.datetime.now()
      elapsed_time = super_batch_processing_end_time - super_batch_processing_start_time
      print(f"elapsed time for processing {super_batch_output_pickle_file}: {elapsed_time}", flush=True)


   aggregated_patterns = counter_to_list(counter, min_row_count)
   sorted_aggregate_patterns = sort_pattern(aggregated_patterns)

   del aggregated_patterns

   super_batch_spm_result_pickles_dirname = os.path.split(super_batch_spm_result_pickles_dirpath)[-1]

   final_output_pickle_fname = "final_output_for__" + super_batch_spm_result_pickles_dirname


   final_output_pickle_fpath = os.path.join(os.path.split(super_batch_spm_result_pickles_dirpath)[0],
                                            final_output_pickle_fname)


   with open(f"{final_output_pickle_fpath}.pickle", 'wb') as fp:
      pickle.dump(sorted_aggregate_patterns, fp)


   all_batch_processing_end_time = datetime.datetime.now()
   all_elapsed_time = all_batch_processing_end_time - all_batch_processing_start_time
   print(f"elapsed time for entire-process for {super_batch_spm_result_pickles_dirpath}: {all_elapsed_time}", flush=True)
   print(f"\nfinal-output saved to : {final_output_pickle_fpath}\n", flush = True)

   del sorted_aggregate_patterns


      # https://github.com/fidelity/seq2pat/blob/1b27c79af4c5d33c8714b9f010dd8ea4efd26d50/sequential/seq2pat.py#L584
      # https://github.com/fidelity/seq2pat/blob/1b27c79af4c5d33c8714b9f010dd8ea4efd26d50/sequential/utils.py#L369C5-L369C23


      # "Motivated" by 'aggregate_patterns' in utils.py

      








