<?php

namespace IPLib\Range;

use IPLib\Address\AddressInterface;
use IPLib\Address\IPv4;
use IPLib\Address\IPv6;
use IPLib\Address\Type as AddressType;
use IPLib\ParseStringFlag;

/**
 * Represents an address range in pattern format (only ending asterisks are supported).
 *
 * @example 127.0.*.*
 * @example ::/8
 */
class Range extends AbstractRange
{
    /**
     * Starting address of the range.
     *
     * @var \IPLib\Address\AddressInterface
     */
    protected $fromAddress;

    /**
     * Final address of the range.
     *
     * @var \IPLib\Address\AddressInterface
     */
    protected $toAddress;

    /**
     * Number of ending asterisks.
     *
     * @var int
     */
    protected $asterisksCount;

    /**
     * The type of the range of this IP range.
     *
     * @var int|false|null false if this range crosses multiple range types, null if yet to be determined
     *
     * @since 1.5.0
     */
    protected $rangeType;

    /**
     * Initializes the instance.
     *
     * @param \IPLib\Address\AddressInterface $fromAddress
     * @param \IPLib\Address\AddressInterface $toAddress
     * @param int $asterisksCount
     */
    public function __construct(AddressInterface $fromAddress, AddressInterface $toAddress)
    {
        $this->fromAddress = $fromAddress;
        $this->toAddress = $toAddress;
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::__toString()
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * @deprecated since 1.17.0: use the parseString() method instead.
     * For upgrading:
     * - if $supportNonDecimalIPv4 is true, use the ParseStringFlag::IPV4_MAYBE_NON_DECIMAL flag
     *
     * @param string|mixed $range
     * @param bool $supportNonDecimalIPv4
     *
     * @return static|null
     *
     * @see \IPLib\Range\Pattern::parseString()
     * @since 1.10.0 added the $supportNonDecimalIPv4 argument
     */
    public static function fromString($range, $supportNonDecimalIPv4 = false)
    {
        return static::parseString($range, ParseStringFlag::MAY_INCLUDE_PORT | ParseStringFlag::MAY_INCLUDE_ZONEID | ($supportNonDecimalIPv4 ? ParseStringFlag::IPV4_MAYBE_NON_DECIMAL : 0));
    }

    /**
     * Try get the range instance starting from its string representation.
     *
     * @param string|mixed $range
     * @param int $flags A combination or zero or more flags
     *
     * @return static|null
     *
     * @since 1.17.0
     * @see \IPLib\ParseStringFlag
     */
    public static function parseString($range, $flags = 0)
    {
        if (!is_string($range) || strpos($range, '-') === false) {
            return null;
        }

        $addresses = explode('-', $range);

        $addressOne = $addresses[0];
        $addressTwo = $addresses[1];

        // we are in ipv4 mode
        if (filter_var($addressOne, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $addressOne = IPv4::parseString($addressOne);
            $addressTwo = IPv4::parseString($addressTwo);
        } elseif (filter_var($addressOne, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $addressOne = IPv6::parseString($addressOne);
            $addressTwo = IPv6::parseString($addressTwo);
        } else {
            return null;
        }

        return new static($addressOne, $addressTwo);
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::toString()
     */
    public function toString($long = false)
    {
        return $this->asSubnet()->toString();
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::getAddressType()
     */
    public function getAddressType()
    {
        return $this->fromAddress->getAddressType();
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::getStartAddress()
     */
    public function getStartAddress()
    {
        return $this->fromAddress;
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::getEndAddress()
     */
    public function getEndAddress()
    {
        return $this->toAddress;
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::getComparableStartString()
     */
    public function getComparableStartString()
    {
        return $this->fromAddress->getComparableString();
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::getComparableEndString()
     */
    public function getComparableEndString()
    {
        return $this->toAddress->getComparableString();
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::asSubnet()
     * @since 1.8.0
     */
    public function asSubnet()
    {
        return new Subnet($this->getStartAddress(), $this->getEndAddress(), $this->getNetworkPrefix());
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::asPattern()
     */
    public function asPattern()
    {
        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::getSubnetMask()
     */
    public function getSubnetMask()
    {
        if ($this->getAddressType() !== AddressType::T_IPv4) {
            return null;
        }
        switch ($this->asterisksCount) {
            case 0:
                $bytes = array(255, 255, 255, 255);
                break;
            case 4:
                $bytes = array(0, 0, 0, 0);
                break;
            default:
                $bytes = array_pad(array_fill(0, 4 - $this->asterisksCount, 255), 4, 0);
                break;
        }

        return IPv4::fromBytes($bytes);
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::getReverseDNSLookupName()
     */
    public function getReverseDNSLookupName()
    {
        return $this->asterisksCount === 0 ? array($this->getStartAddress()->getReverseDNSLookupName()) : $this->asSubnet()->getReverseDNSLookupName();
    }

    /**
     * {@inheritdoc}
     *
     * @see \IPLib\Range\RangeInterface::getSize()
     */
    public function getSize()
    {
        $fromAddress = $this->fromAddress;
        $maxPrefix = $fromAddress::getNumberOfBits();
        $prefix = $this->getNetworkPrefix();

        return pow(2, ($maxPrefix - $prefix));
    }

    /**
     * @return float|int
     */
    private function getNetworkPrefix()
    {
        switch ($this->getAddressType()) {
            case AddressType::T_IPv4:
                return 8 * (4 - $this->asterisksCount);
            case AddressType::T_IPv6:
                return 16 * (8 - $this->asterisksCount);
        }
    }
}
