import os
import shutil
import matplotlib.pyplot as plt 
import matplotlib
import numpy as np 
import scipy.stats as stats
import scipy.optimize as opt
import pandas as pd 
import random
import xlrd
import seaborn as sns
from pprint import pprint
from pandas.core.frame import DataFrame
import sys
import itertools
import matplotlib.gridspec as gridspec

mycolor = [(i/256, j/256, k/256) for (i,j,k) in [(31, 119, 180), (214, 39, 40), (255, 127, 14), (227, 119, 194), (44, 160, 44), (148, 103, 189), (23, 190, 207), (109, 67, 45)]]


data_path="./bug-realworld.xlsx"
sheetname="bugcnt"

nrows=160
ncols=3
sns.set_style('whitegrid')

def main():
    script_path = sys.path[0]
    os.chdir(script_path)
    all_data = xlrd.open_workbook(os.path.join(script_path,data_path))
    all_table = all_data.sheet_by_name(sheetname)

    # all_fuzzer=["AFL","AFLFast","Angora","Hfuzz","QSYM","T-Fuzz","VUzzer64"]
    all_prog=["exiv2", "gdk", "imginfo", "jhead", "tiffsplit", "lame", "mp3gain", "wav2swf", "ffmpeg", "flvmeta", "mp42aac", "cflow", "infotocap", "jq", "mujs", "pdftotext", "sqlite3", "nm", "objdump", "tcpdump"]

    fig = plt.figure(figsize=(16,6))
    outer = gridspec.GridSpec(2, 1, wspace=0.2, hspace=0.2, height_ratios= [1, 15])
    a0 = outer[0]
    inner = gridspec.GridSpecFromSubplotSpec(4,5, subplot_spec=outer[1], wspace=0.2, hspace=0.45)
    

    index=-1
    for prog in all_prog:
        index +=1
        # print(prog)
        res_dict={}
        for i in range(0, nrows):
            tmp_value=all_table.cell_value(i,0)
            if prog in tmp_value:
                fuzzer = tmp_value.split('_')[0]
                tmp_bug = eval(all_table.cell_value(i,1))
                res_dict[fuzzer] = tmp_bug

        # print(res_dict)
        res_dict1=dict(sorted(res_dict.items(), key=lambda d:d[0]))

        keys = list(res_dict1.keys())
        values = list(res_dict1.values())
        ax = plt.Subplot(fig, inner[index])
        ax.set_xticks([])
        fig.add_subplot(ax)
        plt.title(prog,fontsize=16)

        ax = sns.boxplot(x=keys, y=values, linewidth=1.1, fliersize=3, palette=mycolor, ax=ax, showmeans=True,
            meanprops={"marker":"s","markerfacecolor":"white", "markeredgecolor":"red", "markersize":3})
        plt.ylim(0, None)
        
        ax.get_xaxis().set_visible(False)
        ax.yaxis.set_major_locator(plt.MaxNLocator(5))


    
    ax=plt.Subplot(fig, outer[0])
    ax.set_ylabel('')
    ax.set_xlabel('')
    fig.add_subplot(ax)
    ax = sns.boxplot(x=[0]*8, y=[0]*8, sym='', hue=keys, linewidth=0, palette=mycolor, ax=ax, boxprops={"linestyle":"None"})
    ax.spines['right'].set_visible(False)
    ax.spines['top'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    plt.xticks([])
    plt.yticks([])
    handles, labels = ax.get_legend_handles_labels()
    plt.legend(handles, labels, loc='center', ncol=8, fontsize=13)

    if os.path.exists(dpath)==False:
        os.makedirs(dpath)
    print("saving")
    plt.savefig("all-real.eps", format='eps',bbox_inches='tight')
    plt.show()



if __name__ == '__main__':
    main()