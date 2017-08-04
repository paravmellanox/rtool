ioping
======

An tool to monitor I/O latency in real time.
It shows disk latency in the same way as ping shows network latency.

Homepage: https://github.com/paravpandit/rtool/

Please send your patches, issues and questions to
https://github.com/paravpandit/rtool/issues/

Supported OS
------------

* GNU/Linux

Packages
--------

None at this time.

Examples
--------

Show RDMA MR registration latency

```
$ rdma_mr_lat -d mlx5_0 -s 4G
```

Show RDMA MR registration latency using huge pages

```
$ rdma_mr_lat -d mlx5_0 -s 1G -u

```

Authors
-------

* Parav Pandit <parav@mellanox.com>

Licensed under GPLv3 (or later) <http://www.gnu.org/licenses/gpl-3.0.txt>
