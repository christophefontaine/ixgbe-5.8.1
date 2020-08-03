// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 1999 - 2020 Intel Corporation. */

#include "ixgbe.h"
#include "ixgbe_common.h"
#include "ixgbe_type.h"

#ifdef IXGBE_SYSFS

#include <linux/module.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/time.h>
#ifdef IXGBE_HWMON
#include <linux/hwmon.h>
#endif

#define to_dev(obj) container_of(obj, struct device, kobj)

const struct vfd_ops *vfd_ops = NULL;

/**
 * __parse_add_rem_bitmap - helper function to parse bitmap data
 * @pdev:   PCI device information struct
 * @buff:   buffer with input data
 * @attr_name:  name of the attribute
 * @data_new:   pointer to input data merged with the old data
 * @data_old:   pointer to old data of the attribute
 *
 * If passed add: set data_new to "data_old || data_input"
 * If passed rem: set data_new to "data_old || ~data_input"
 */
static int __parse_add_rem_bitmap(struct pci_dev *pdev, const char *buff,
                  const char *attr_name,
                  unsigned long *data_new,
                  unsigned long *data_old)
{
    int ret = 0;
    char *p;

    if (strstr(buff, "add")) {
        p = strstr(buff, "add");
        bitmap_zero(data_new, VLAN_N_VID);

        ret = bitmap_parselist(p + sizeof("add"), data_new, VLAN_N_VID);
        if (ret) {
            dev_err(&pdev->dev,
                "add %s: input error %d\n", attr_name, ret);
            return ret;
        }

        bitmap_or(data_new, data_new, data_old, VLAN_N_VID);
    } else if (strstr(buff, "rem")) {
        p = strstr(buff, "rem");
        bitmap_zero(data_new, VLAN_N_VID);

        ret = bitmap_parselist(p + sizeof("rem"), data_new, VLAN_N_VID);
        if (ret) {
            dev_err(&pdev->dev,
                "rem %s: input error %d\n", attr_name, ret);
            return ret;
        }

        /* new = old & ~rem */
        bitmap_andnot(data_new, data_old, data_new, VLAN_N_VID);
    } else {
        dev_err(&pdev->dev, "set %s: invalid input string", attr_name);
        return -EINVAL;
    }
    return 0;
}


/* Handlers for each VFd operation */

/**
 * __get_pf_pdev - helper function to get the pdev
 * @kobj:   kobject passed
 * @pdev:   PCI device information struct
 */
static int __get_pf_pdev(struct kobject *kobj, struct pci_dev **pdev)
{
    struct device *dev;

    if (!kobj->parent)
        return -EINVAL;

    /* get pdev */
    dev = to_dev(kobj->parent);
    *pdev = to_pci_dev(dev);

    return 0;
}


/**
 * __get_pdev_and_vfid - helper function to get the pdev and the vf id
 * @kobj:   kobject passed
 * @pdev:   PCI device information struct
 * @vf_id:  VF id of the VF under consideration
 */
static int __get_pdev_and_vfid(struct kobject *kobj, struct pci_dev **pdev,
                   int *vf_id)
{
    struct device *dev;

    if (!kobj->parent->parent)
        return -EINVAL;

    /* get pdev */
    dev = to_dev(kobj->parent->parent);
    *pdev = to_pci_dev(dev);

    /* get vf_id */
    if (kstrtoint(kobj->name, 10, vf_id) != 0) {
        dev_err(&(*pdev)->dev, "Failed to convert %s to vf_id\n",
            kobj->name);
        return -EINVAL;
    }

    return 0;
}


/**
 * vfd_trunk_show - handler for trunk show function
 * @kobj:   kobject being called
 * @attr:   struct kobj_attribute
 * @buff:   buffer with input data
 *
 * Get current data from driver and copy to buffer
 **/
static ssize_t vfd_trunk_show(struct kobject *kobj,
                  struct kobj_attribute *attr, char *buff)
{
    struct pci_dev *pdev;
    int vf_id, ret = 0;

    DECLARE_BITMAP(data, VLAN_N_VID);
    bitmap_zero(data, VLAN_N_VID);

    if (!vfd_ops || !vfd_ops->get_trunk)
        return -EOPNOTSUPP;

    ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
    if (ret)
        return ret;

    ret = vfd_ops->get_trunk(pdev, vf_id, data);
    if (ret)
        ret = bitmap_print_to_pagebuf(1, buff, data, VLAN_N_VID);

    return ret;
}

/**
 * vfd_trunk_store - handler for trunk store function
 * @kobj:   kobject being called
 * @attr:   struct kobj_attribute
 * @buff:   buffer with input data
 * @count:  size of buff
 *
 * Get current data from driver, compose new data based on input values
 * depending on "add" or "rem" command, and pass new data to the driver to set.
 *
 * On success return count, indicating that we used the whole buffer. On
 * failure return a negative error condition.
 **/
static ssize_t vfd_trunk_store(struct kobject *kobj,
                   struct kobj_attribute *attr,
                   const char *buff, size_t count)
{
    unsigned long *data_old, *data_new;
    struct pci_dev *pdev;
    int vf_id, ret = 0;

    if (!vfd_ops || !vfd_ops->set_trunk || !vfd_ops->get_trunk)
        return -EOPNOTSUPP;

    ret = __get_pdev_and_vfid(kobj, &pdev, &vf_id);
    if (ret)
        return ret;

    data_old = kcalloc(BITS_TO_LONGS(VLAN_N_VID), sizeof(unsigned long),
               GFP_KERNEL);
    if (!data_old)
        return -ENOMEM;
    data_new = kcalloc(BITS_TO_LONGS(VLAN_N_VID), sizeof(unsigned long),
               GFP_KERNEL);
    if (!data_new) {
        kfree(data_old);
        return -ENOMEM;
    }

    ret = vfd_ops->get_trunk(pdev, vf_id, data_old);
    if (ret < 0)
        goto err_free;

    ret = __parse_add_rem_bitmap(pdev, buff, "trunk", data_new, data_old);
    if (ret)
        goto err_free;

    if (!bitmap_equal(data_new, data_old, VLAN_N_VID))
        ret = vfd_ops->set_trunk(pdev, vf_id, data_new);

err_free:
    kfree(data_old);
    kfree(data_new);
    return ret ? ret : count;
}


static struct kobj_attribute trunk_attribute =
    __ATTR(trunk, 0644, vfd_trunk_show, vfd_trunk_store);

static struct attribute *s_attrs[] = {
    &trunk_attribute.attr,
    NULL
};

static struct attribute_group vfd_group = {
    .attrs = s_attrs,
};


#ifdef IXGBE_HWMON
/* hwmon callback functions */
static ssize_t ixgbe_hwmon_show_location(struct device __always_unused *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct hwmon_attr *ixgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	return snprintf(buf, PAGE_SIZE, "loc%u\n",
		       ixgbe_attr->sensor->location);
}

static ssize_t ixgbe_hwmon_show_temp(struct device __always_unused *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct hwmon_attr *ixgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value;

	/* reset the temp field */
	ixgbe_attr->hw->mac.ops.get_thermal_sensor_data(ixgbe_attr->hw);

	value = ixgbe_attr->sensor->temp;

	/* display millidegree */
	value *= 1000;

	return snprintf(buf, PAGE_SIZE, "%u\n", value);
}

static ssize_t ixgbe_hwmon_show_cautionthresh(struct device __always_unused *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct hwmon_attr *ixgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value = ixgbe_attr->sensor->caution_thresh;

	/* display millidegree */
	value *= 1000;

	return snprintf(buf, PAGE_SIZE, "%u\n", value);
}

static ssize_t ixgbe_hwmon_show_maxopthresh(struct device __always_unused *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct hwmon_attr *ixgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value = ixgbe_attr->sensor->max_op_thresh;

	/* display millidegree */
	value *= 1000;

	return snprintf(buf, PAGE_SIZE, "%u\n", value);
}

/**
 * ixgbe_add_hwmon_attr - Create hwmon attr table for a hwmon sysfs file.
 * @adapter: pointer to the adapter structure
 * @offset: offset in the eeprom sensor data table
 * @type: type of sensor data to display
 *
 * For each file we want in hwmon's sysfs interface we need a device_attribute
 * This is included in our hwmon_attr struct that contains the references to
 * the data structures we need to get the data to display.
 */
static int ixgbe_add_hwmon_attr(struct ixgbe_adapter *adapter,
				unsigned int offset, int type) {
	unsigned int n_attr;
	struct hwmon_attr *ixgbe_attr;
#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS

	n_attr = adapter->ixgbe_hwmon_buff->n_hwmon;
	ixgbe_attr = &adapter->ixgbe_hwmon_buff->hwmon_list[n_attr];
#else
	int rc;

	n_attr = adapter->ixgbe_hwmon_buff.n_hwmon;
	ixgbe_attr = &adapter->ixgbe_hwmon_buff.hwmon_list[n_attr];
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */

	switch (type) {
	case IXGBE_HWMON_TYPE_LOC:
		ixgbe_attr->dev_attr.show = ixgbe_hwmon_show_location;
		snprintf(ixgbe_attr->name, sizeof(ixgbe_attr->name),
			 "temp%u_label", offset + 1);
		break;
	case IXGBE_HWMON_TYPE_TEMP:
		ixgbe_attr->dev_attr.show = ixgbe_hwmon_show_temp;
		snprintf(ixgbe_attr->name, sizeof(ixgbe_attr->name),
			 "temp%u_input", offset + 1);
		break;
	case IXGBE_HWMON_TYPE_CAUTION:
		ixgbe_attr->dev_attr.show = ixgbe_hwmon_show_cautionthresh;
		snprintf(ixgbe_attr->name, sizeof(ixgbe_attr->name),
			 "temp%u_max", offset + 1);
		break;
	case IXGBE_HWMON_TYPE_MAX:
		ixgbe_attr->dev_attr.show = ixgbe_hwmon_show_maxopthresh;
		snprintf(ixgbe_attr->name, sizeof(ixgbe_attr->name),
			 "temp%u_crit", offset + 1);
		break;
	default:
		return -EPERM;
	}

	/* These always the same regardless of type */
	ixgbe_attr->sensor =
		&adapter->hw.mac.thermal_sensor_data.sensor[offset];
	ixgbe_attr->hw = &adapter->hw;
	ixgbe_attr->dev_attr.store = NULL;
	ixgbe_attr->dev_attr.attr.mode = 0444;
	ixgbe_attr->dev_attr.attr.name = ixgbe_attr->name;

#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	sysfs_attr_init(&ixgbe_attr->dev_attr.attr);

	adapter->ixgbe_hwmon_buff->attrs[n_attr] = &ixgbe_attr->dev_attr.attr;

	++adapter->ixgbe_hwmon_buff->n_hwmon;

	return 0;
#else
	rc = device_create_file(pci_dev_to_dev(adapter->pdev),
				&ixgbe_attr->dev_attr);

	if (rc == 0)
		++adapter->ixgbe_hwmon_buff.n_hwmon;

	return rc;
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */
}
#endif /* IXGBE_HWMON */

static void ixgbe_sysfs_del_adapter(struct ixgbe_adapter __maybe_unused *adapter)
{
#ifdef IXGBE_HWMON
#ifndef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	int i;

	if (adapter == NULL)
		return;

	for (i = 0; i < adapter->ixgbe_hwmon_buff.n_hwmon; i++) {
		device_remove_file(pci_dev_to_dev(adapter->pdev),
			   &adapter->ixgbe_hwmon_buff.hwmon_list[i].dev_attr);
	}

	kfree(adapter->ixgbe_hwmon_buff.hwmon_list);

	if (adapter->ixgbe_hwmon_buff.device)
		hwmon_device_unregister(adapter->ixgbe_hwmon_buff.device);
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */
#endif /* IXGBE_HWMON */
}

/* called from ixgbe_main.c */
void ixgbe_sysfs_exit(struct ixgbe_adapter *adapter)
{
	ixgbe_sysfs_del_adapter(adapter);
}

/* called from ixgbe_main.c */
int ixgbe_sysfs_init(struct ixgbe_adapter *adapter)
{
	int rc = 0;
#ifdef IXGBE_HWMON
#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	struct hwmon_buff *ixgbe_hwmon;
	struct device *hwmon_dev;
#else
	struct hwmon_buff *ixgbe_hwmon = &adapter->ixgbe_hwmon_buff;
	int n_attrs;
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */
	unsigned int i;
#endif /* IXGBE_HWMON */

#ifdef IXGBE_HWMON
	/* If this method isn't defined we don't support thermals */
	if (adapter->hw.mac.ops.init_thermal_sensor_thresh == NULL) {
		goto no_thermal;
	}

	/* Don't create thermal hwmon interface if no sensors present */
	if (adapter->hw.mac.ops.init_thermal_sensor_thresh(&adapter->hw))
		goto no_thermal;

#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	ixgbe_hwmon = devm_kzalloc(&adapter->pdev->dev, sizeof(*ixgbe_hwmon),
				   GFP_KERNEL);

	if (!ixgbe_hwmon) {
		rc = -ENOMEM;
		goto exit;
	}

	adapter->ixgbe_hwmon_buff = ixgbe_hwmon;
#else
	/*
	 * Allocation space for max attributs
	 * max num sensors * values (loc, temp, max, caution)
	 */
	n_attrs = IXGBE_MAX_SENSORS * 4;
	ixgbe_hwmon->hwmon_list = kcalloc(n_attrs, sizeof(struct hwmon_attr),
					  GFP_KERNEL);

	if (!ixgbe_hwmon->hwmon_list) {
		rc = -ENOMEM;
		goto err;
	}
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */

	for (i = 0; i < IXGBE_MAX_SENSORS; i++) {
		/*
		 * Only create hwmon sysfs entries for sensors that have
		 * meaningful data for.
		 */
		if (adapter->hw.mac.thermal_sensor_data.sensor[i].location == 0)
			continue;

		/* Bail if any hwmon attr struct fails to initialize */
		rc = ixgbe_add_hwmon_attr(adapter, i, IXGBE_HWMON_TYPE_CAUTION);
		if (rc)
			goto err;
		rc = ixgbe_add_hwmon_attr(adapter, i, IXGBE_HWMON_TYPE_LOC);
		if (rc)
			goto err;
		rc = ixgbe_add_hwmon_attr(adapter, i, IXGBE_HWMON_TYPE_TEMP);
		if (rc)
			goto err;
		rc = ixgbe_add_hwmon_attr(adapter, i, IXGBE_HWMON_TYPE_MAX);
		if (rc)
			goto err;
	}

#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
	ixgbe_hwmon->groups[0] = &ixgbe_hwmon->group;
	ixgbe_hwmon->group.attrs = ixgbe_hwmon->attrs;

	hwmon_dev = devm_hwmon_device_register_with_groups(&adapter->pdev->dev,
							   "ixgbe",
							   ixgbe_hwmon,
							   ixgbe_hwmon->groups);

	if (IS_ERR(hwmon_dev)) {
		rc = PTR_ERR(hwmon_dev);
		goto exit;
	}

#else
	ixgbe_hwmon->device =
		hwmon_device_register(pci_dev_to_dev(adapter->pdev));

	if (IS_ERR(ixgbe_hwmon->device)) {
		rc = PTR_ERR(ixgbe_hwmon->device);
		goto err;
	}

#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS */
no_thermal:
#endif /* IXGBE_HWMON */
	goto exit;

err:
	ixgbe_sysfs_del_adapter(adapter);
exit:
	return rc;
}


/**
 * create_vfd_sysfs - create sysfs hierarchy used by VF-d
 * @pdev:       PCI device information struct
 * @num_alloc_vfs:  number of VFs to allocate
 *
 * If the kobjects were not able to be created, NULL will be returned.
 **/
struct vfd_objects *create_vfd_sysfs(struct pci_dev *pdev, int num_alloc_vfs)
{
    struct vfd_objects *vfd_obj;
    struct kobject *vf_kobj;
    char kname[4];
    int ret, i;

    vfd_obj = kzalloc(sizeof(*vfd_obj) +
              sizeof(struct kobject *)*num_alloc_vfs, GFP_KERNEL);
    if (!vfd_obj)
        return NULL;

    vfd_obj->num_vfs = num_alloc_vfs;

    vfd_obj->sriov_kobj = kobject_create_and_add("sriov", &pdev->dev.kobj);
    if (!vfd_obj->sriov_kobj)
        goto err_sysfs;

    dev_info(&pdev->dev, "created %s sysfs", vfd_obj->sriov_kobj->name);
    
    for(i = 0; i < vfd_obj->num_vfs; i++) {
        int length = snprintf(kname, sizeof(kname), "%d", i);
        if (length >= sizeof(kname)) {
            dev_err(&pdev->dev,
                "cannot request %d vfs, try again with smaller number of vfs\n",
                i);
            --i;
            ret = -EINVAL;
            //TODO: goto err_vfs_sysfs;
        }
        vf_kobj = kobject_create_and_add(kname, vfd_obj->sriov_kobj);
                if (!vf_kobj) {
            dev_err(&pdev->dev,
                "failed to create VF kobj: %s\n", kname);
            i--;
            ret = -ENOMEM;
            //TODO: goto err_vfs_sysfs;
        }
        dev_info(&pdev->dev, "created VF %s sysfs", vf_kobj->name);
        vfd_obj->vf_kobj[i] = vf_kobj;

        /* create VF sys attr */
        ret = sysfs_create_group(vfd_obj->vf_kobj[i], &vfd_group);
        if (ret) {
            dev_err(&pdev->dev, "failed to create VF sys attribute: %d", i);
            //TODO: goto err_vfs_sysfs;
        }
    }

    return vfd_obj;

err_sysfs:
    kobject_put(vfd_obj->sriov_kobj);
    kfree(vfd_obj);
    return NULL;
}

/**
 * destroy_vfd_sysfs - destroy sysfs hierarchy used by VF-d
 * @pdev:   PCI device information struct
 * @vfd_obj:    VF-d kobjects information struct
 **/
void destroy_vfd_sysfs(struct pci_dev *pdev, struct vfd_objects *vfd_obj)
{
    int i;

    for (i = 0; i < vfd_obj->num_vfs; i++) {
        dev_info(&pdev->dev, "deleting VF %s sysfs",
             vfd_obj->vf_kobj[i]->name);
        kobject_put(vfd_obj->vf_kobj[i]);
    }

    dev_info(&pdev->dev, "deleting %s sysfs", vfd_obj->sriov_kobj->name);
    kobject_put(vfd_obj->sriov_kobj);
    kfree(vfd_obj);
}
#endif /* IXGBE_SYSFS */
